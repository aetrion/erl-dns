%% Copyright (c) 2012-2020, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Worker module that processes a single DNS packet.
-module(erldns_worker_process).

-include_lib("dns_erlang/include/dns.hrl").
-include_lib("opentelemetry_api/include/otel_tracer.hrl").

-behaviour(gen_server).

-export([start_link/1]).
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-define(MAX_PACKET_SIZE, 512).
-define(REDIRECT_TO_LOOPBACK, false).
-define(LOOPBACK_DEST, {127, 0, 0, 10}).

-if(?REDIRECT_TO_LOOPBACK).

-define(DEST_HOST(_Host), ?LOOPBACK_DEST).

-else.

-define(DEST_HOST(Host), Host).

-endif.

-record(state, {}).

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init(_Args) ->
    {ok, #state{}}.

% Process a TCP request. Does not truncate the response.
handle_call({process, DecodedMessage, Socket, {tcp, Address}, SpanCtx}, _From, State) ->
    ?set_current_span(SpanCtx),
    % Uncomment this and the function implementation to simulate a timeout when
    % querying www.example.com with the test zones
    % simulate_timeout(DecodedMessage),
    Response = ?with_span(<<"synthesize_answer">>, #{},
        fun(_SpanCtx) ->
            erldns_handler:handle(DecodedMessage, {tcp, Address})
        end
    ),
    EncodedMessage = ?with_span(<<"encode_message">>, #{},
        fun(_SpanCtx) ->
            ?set_attributes([
                {<<"rcode">>, Response#dns_message.rc},
                {<<"aa">>, Response#dns_message.aa},
                {<<"ra">>, Response#dns_message.ra},
                {<<"answers">>, length(Response#dns_message.answers)}
            ]),
            erldns_encoder:encode_message(Response)
        end
    ),
    ?with_span(<<"send_tcp_message">>, #{},
        fun(_SpanCtx) ->
            send_tcp_message(Socket, EncodedMessage)
        end
    ),
    {reply, ok, State};
% Process a UDP request. May truncate the response.
handle_call({process, DecodedMessage, Socket, Port, {udp, Host}, SpanCtx}, _From, State) ->
    ?set_current_span(SpanCtx),
    % Uncomment this and the function implementation to simulate a timeout when
    % querying www.example.com with the test zones
    % simulate_timeout(DecodedMessage),
    Response = ?with_span(<<"synthesize_answer">>, #{},
                    fun(_SpanCtx) ->
                        erldns_handler:handle(DecodedMessage, {udp, Host})
                    end
                ),
    DestHost = ?DEST_HOST(Host),

    Result = ?with_span(<<"encode_message">>, #{},
                 fun(_SpanCtx) ->
                    ?set_attributes([
                        {<<"rcode">>, Response#dns_message.rc},
                        {<<"aa">>, Response#dns_message.aa},
                        {<<"ra">>, Response#dns_message.ra},
                        {<<"answers">>, length(Response#dns_message.answers)}
                    ]),
                     erldns_encoder:encode_message(Response, [{max_size, max_payload_size(Response)}])
                 end
             ),
    case Result of
        {false, EncodedMessage} ->
            % lager:debug("Sending encoded response to ~p", [DestHost]),
            gen_udp:send(Socket, DestHost, Port, EncodedMessage);
        {true, EncodedMessage, Message} when is_record(Message, dns_message) ->
            gen_udp:send(Socket, DestHost, Port, EncodedMessage);
        {false, EncodedMessage, _TsigMac} ->
            gen_udp:send(Socket, DestHost, Port, EncodedMessage);
        {true, EncodedMessage, _TsigMac, _Message} ->
            gen_udp:send(Socket, DestHost, Port, EncodedMessage)
    end,
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal private functions

send_tcp_message(Socket, EncodedMessage) ->
    BinLength = byte_size(EncodedMessage),
    TcpEncodedMessage = <<BinLength:16, EncodedMessage/binary>>,
    gen_tcp:send(Socket, TcpEncodedMessage).

%% Determine the max payload size by looking for additional
%% options passed by the client.
max_payload_size(Message) ->
    case Message#dns_message.additional of
        [Opt | _] when is_record(Opt, dns_optrr) ->
            case Opt#dns_optrr.udp_payload_size of
                [] ->
                    ?MAX_PACKET_SIZE;
                _ ->
                    Opt#dns_optrr.udp_payload_size
            end;
        _ ->
            ?MAX_PACKET_SIZE
    end.

%simulate_timeout(DecodedMessage) ->
  %[Question] = DecodedMessage#dns_message.questions,
  %Name = Question#dns_query.name,
  %lager:info("qname: ~p", [Name]),
  %case Name of

    %<<"www.example.com">> ->
      %timer:sleep(3000);

    %_ ->
      %ok

  %end.
