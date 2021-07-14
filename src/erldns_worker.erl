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

%% @doc Worker module that asynchronously accepts a single DNS packet and
%% hands it to a worker process that has a set timeout.
-module(erldns_worker).

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

-record(state, {worker_process_sup, worker_process}).

erlang_proc_message_queue_len() ->
    case process_info(self(), message_queue_len) of
        undefined -> <<"undefined">>;
        {message_queue_len, Count} -> Count
    end.

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init([WorkerId]) ->
    {ok, WorkerProcessSup} = erldns_worker_process_sup:start_link([WorkerId]),
    WorkerProcess = lists:last(supervisor:which_children(WorkerProcessSup)),
    {ok, #state{worker_process_sup = WorkerProcessSup, worker_process = WorkerProcess}}.

handle_call(_Request, From, State) ->
    lager:debug("Received unexpected call (from: ~p)", [From]),
    {reply, ok, State}.

handle_cast({tcp_query, Socket, Bin}, State) ->
    ?with_span(<<"erldns_tcp_worker">>, #{},
        fun(SpanCtx) ->
            case handle_tcp_dns_query(Socket, Bin, SpanCtx, {State#state.worker_process_sup, State#state.worker_process}) of
                ok ->
                    {noreply, State};
                {error, timeout, NewWorkerPid} ->
                    {Id, _, Type, Modules} = State#state.worker_process,
                    {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
                Error ->
                    lager:error("Error handling TCP query (module: ~p, event: ~p, error: ~p)", [?MODULE, handle_tcp_query_error, Error]),
                    {noreply, State}
            end
        end
    );
handle_cast({udp_query, Socket, Host, Port, Bin}, State) ->
    ?with_span(<<"erldns_udp_worker">>, #{},
           fun(_SpanCtx) ->
                ?set_attributes([{host, Host}, {port, Port}, {worker_process, State#state.worker_process}]),
                ?set_attributes([{erlang_port_count, erlang:system_info(port_count)},
                                 {erlang_proc_count, erlang:system_info(process_count)},
                                 {erlang_run_queue, erlang:statistics(run_queue)},
                                 {erlang_proc_message_queue_len, erlang_proc_message_queue_len()}
                            ]),

                case handle_udp_dns_query(Socket, Host, Port, Bin, ?current_span_ctx, {State#state.worker_process_sup, State#state.worker_process}) of
                    ok ->
                        ?set_attributes([{status, <<"ok">>}]),
                        {noreply, State};
                    {error, timeout, NewWorkerPid} ->
                        ?set_attributes([{status, <<"timeout">>}]),
                        {Id, _, Type, Modules} = State#state.worker_process,
                        {noreply, State#state{worker_process = {Id, NewWorkerPid, Type, Modules}}};
                    Error ->
                        ?set_attributes([{status, <<"error">>}]),
                        lager:error("Error handling UDP query (module: ~p, event: ~p, error: ~p)", [?MODULE, handle_udp_query_error, Error]),
                        {noreply, State}
                end
            end
    );
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% @doc Handle DNS query that comes in over TCP
-spec handle_tcp_dns_query(gen_tcp:socket(), iodata(), map(), {pid(), term()}) -> ok | {error, timeout} | {error, timeout, pid()}.
handle_tcp_dns_query(Socket, <<_Len:16, Bin/binary>>, SpanCtx, {WorkerProcessSup, WorkerProcess}) ->
    ?set_current_span(SpanCtx),
    ?with_span(<<"handle_tcp_dns_query">>, #{},
                fun(_SpanCtx) ->
                    case inet:peername(Socket) of
                        {ok, {Address, _Port}} ->
                            erldns_events:notify({?MODULE, start_tcp, [{host, Address}]}),
                            Result =
                                case Bin of
                                    <<>> ->
                                        ok;
                                    _ ->
                                        case erldns_decoder:decode_message(Bin) of
                                            {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                                                ?set_attributes([{status, <<"trailing_garbage">>}]),
                                                lager:info("Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)",
                                                        [?MODULE, decode_message_trailing_garbage, DecodedMessage, TrailingGarbage]),
                                                % erldns_events:notify({?MODULE, decode_message_trailing_garbage, {DecodedMessage, TrailingGarbage}}),
                                                handle_decoded_tcp_message(DecodedMessage, Socket, Address, SpanCtx, {WorkerProcessSup, WorkerProcess});
                                            {Error, Message, _} ->
                                                ?set_attributes([{status, <<"error">>}]),
                                                lager:error("Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)",
                                                            [?MODULE, decode_message_error, Error, Message]),
                                                % erldns_events:notify({?MODULE, decode_message_error, {Error, Message}}),
                                                ok;
                                            DecodedMessage ->
                                                Query = lists:last(DecodedMessage#dns_message.questions),
                                                ?set_attributes([
                                                    {status, <<"ok">>},
                                                    {qr, DecodedMessage#dns_message.qr},
                                                    {rd, DecodedMessage#dns_message.rd},
                                                    {ad, DecodedMessage#dns_message.ad},
                                                    {qname, Query#dns_query.name},
                                                    {qtype, dns:type_name(Query#dns_query.type)}
                                                ]),
                                                handle_decoded_tcp_message(DecodedMessage, Socket, Address, SpanCtx, {WorkerProcessSup, WorkerProcess})
                                        end
                                end,
                            erldns_events:notify({?MODULE, end_tcp, [{host, Address}]}),
                            gen_tcp:close(Socket),
                            Result;
                        {error, Reason} ->
                            erldns_events:notify({?MODULE, tcp_error, Reason})
                    end
                end
    );
handle_tcp_dns_query(Socket, BadPacket, SpanCtx, _) ->
    ?set_current_span(SpanCtx),
    ?with_span(<<"handle_tcp_dns_query">>, #{},
                fun(_SpanCtx) ->
                    ?set_attributes([{status, <<"bad_packet">>}]),
                    lager:error("Received bad packet (module: ~p, event: ~p, protocol: ~p, packet: ~p)", [?MODULE, bad_packet, tcp, BadPacket]),
                    % erldns_events:notify({?MODULE, bad_packet, {tcp, BadPacket}}),
                    gen_tcp:close(Socket)
                end
    ).

handle_decoded_tcp_message(DecodedMessage, Socket, Address, SpanCtx, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
    ?set_current_span(SpanCtx),
    ?with_span(<<"handle_decoded_tcp_message">>, #{},
        fun(_SpanCtx) ->
            case DecodedMessage#dns_message.qr of
                false ->
                    try gen_server:call(WorkerProcessPid, {process, DecodedMessage, Socket, {tcp, Address}, SpanCtx}, _Timeout = erldns_config:ingress_tcp_request_timeout()) of
                        _ ->
                            ok
                    catch
                        exit:{timeout, _} ->
                            ?set_attributes([{status, <<"timeout">>}]),
                            erldns_events:notify({?MODULE, timeout}),
                            handle_timeout(WorkerProcessSup, WorkerProcessId);
                        Error:Reason ->
                            ?set_attributes([{status, <<"error">>}]),
                            lager:error("Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)",
                                        [?MODULE, process_crashed, tcp, Error, Reason, DecodedMessage]),
                            {error, {Error, Reason}}
                    end;
                true ->
                    {error, not_a_question}
            end
        end
    ).

%% @doc Handle DNS query that comes in over UDP
-spec handle_udp_dns_query(gen_udp:socket(), gen_udp:ip(), inet:port_number(), binary(), map(), {pid(), term()}) ->
                              ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, pid()}.
handle_udp_dns_query(Socket, Host, Port, Bin, SpanCtx, {WorkerProcessSup, WorkerProcess}) ->
    erldns_events:notify({?MODULE, start_udp, [{host, Host}]}),
    ?set_current_span(SpanCtx),
    Result = ?with_span(<<"handle_udp_dns_query">>, #{},
                fun(_SpanCtx) ->
                    case erldns_decoder:decode_message(Bin) of
                        {trailing_garbage, DecodedMessage, TrailingGarbage} ->
                            ?set_attributes([{status, <<"trailing_garbage">>}]),
                            lager:info("Decoded message included trailing garbage (module: ~p, event: ~p, message: ~p, garbage: ~p)",
                                    [?MODULE, decode_message_trailing_garbage, DecodedMessage, TrailingGarbage]),
                            %erldns_events:notify({?MODULE, decode_message_trailing_garbage, {DecodedMessage, TrailingGarbage}}),
                            handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, SpanCtx, {WorkerProcessSup, WorkerProcess});
                        {Error, Message, _} ->
                            ?set_attributes([{status, <<"error">>}]),
                            lager:error("Error decoding message (module: ~p, event: ~p, error: ~p, message: ~p)", [?MODULE, decode_message_error, Error, Message]),
                            % erldns_events:notify({?MODULE, decode_message_error, {Error, Message}}),
                            ok;
                        DecodedMessage ->
                            Query = lists:last(DecodedMessage#dns_message.questions),
                            ?set_attributes([
                                {status, <<"ok">>},
                                {qr, DecodedMessage#dns_message.qr},
                                {rd, DecodedMessage#dns_message.rd},
                                {ad, DecodedMessage#dns_message.ad},
                                {qname, Query#dns_query.name},
                                {qtype, dns:type_name(Query#dns_query.type)}
                            ]),
                            handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, SpanCtx, {WorkerProcessSup, WorkerProcess})
                    end
                end
    ),
    erldns_events:notify({?MODULE, end_udp, [{host, Host}]}),
    Result.

-spec handle_decoded_udp_message(dns:message(), gen_udp:socket(), gen_udp:ip(), inet:port_number(), map(), {pid(), term()}) ->
                                    ok | {error, not_owner | timeout | inet:posix() | atom()} | {error, timeout, term()}.
handle_decoded_udp_message(DecodedMessage, Socket, Host, Port, SpanCtx, {WorkerProcessSup, {WorkerProcessId, WorkerProcessPid, _, _}}) ->
    ?set_current_span(SpanCtx),
    ?with_span(<<"handle_decoded_udp_message">>, #{},
        fun(_SpanCtx) ->
            case DecodedMessage#dns_message.qr of
                false ->
                    try gen_server:call(WorkerProcessPid, {process, DecodedMessage, Socket, Port, {udp, Host}, SpanCtx}, _Timeout = erldns_config:ingress_udp_request_timeout()) of
                        _ ->
                            ok
                    catch
                        exit:{timeout, _} ->
                            ?set_attributes([{status, <<"timeout">>}]),
                            lager:info("Worker timeout (module: ~p, event: ~p, protocol: ~p, message: ~p)", [?MODULE, timeout, udp, DecodedMessage]),
                            erldns_events:notify({?MODULE, timeout}),
                            handle_timeout(WorkerProcessSup, WorkerProcessId);
                        Error:Reason ->
                            ?set_attributes([{status, <<"error">>}]),
                            lager:error("Worker process crashed (module: ~p, event: ~p, protocol: ~p, error: ~p, reason: ~p, message: ~p)",
                                        [?MODULE, process_crashed, udp, Error, Reason, DecodedMessage]),
                            % erldns_events:notify({?MODULE, process_crashed, {udp, Error, Reason, DecodedMessage}}),
                            {error, {Error, Reason}}
                    end;
                true ->
                    {error, not_a_question}
            end
    end).

-spec handle_timeout(pid(), term()) -> {error, timeout, term()} | {error, timeout}.
handle_timeout(WorkerProcessSup, WorkerProcessId) ->
    TerminateResult = supervisor:terminate_child(WorkerProcessSup, WorkerProcessId),
    lager:debug("Terminate result: ~p", [TerminateResult]),

    case supervisor:restart_child(WorkerProcessSup, WorkerProcessId) of
        {ok, NewChild} ->
            {error, timeout, NewChild};
        {ok, NewChild, _} ->
            {error, timeout, NewChild};
        {error, Error} ->
            erldns_events:notify({?MODULE, restart_failed, {Error}}),
            {error, timeout}
    end.
