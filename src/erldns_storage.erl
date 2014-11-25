%% Copyright (c) 2014, SiftLogic LLC
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

-module(erldns_storage).

-behaviour(gen_server).

%% inter-module API
-export([start_link/0]).

%% API
-export([create/1,
         insert/2,
         delete_table/1,
         delete/2,
         backup_table/1,
         backup_tables/0,
         select/2,
         select/3,
         foldl/3,
         empty_table/1]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-export([load_zones/0,
         load_zones/1]).

-record(state, {}).

-define(POLL_WAIT_HOURS, 1).
-define(FILENAME, "zones.json").

%% Gen Server Callbacks
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    %%This call to handle_info starts the timer to backup tables in the given interval.
    {ok, #state{}, 0}.

handle_call(_Request, _From, State) ->
    {reply, ok, State, 0}.

handle_cast(_Msg, State) ->
    {noreply, State, 0}.

%% @doc Backups the tables in the given period
handle_info(timeout, State) ->
    Before = now(),
    ok = backup_tables(),
    TimeSpentMs = timer:now_diff(now(), Before) div 1000,
    {noreply, State, max((?POLL_WAIT_HOURS * 60000) - TimeSpentMs, 0)};
handle_info(_Info, State) ->
    {noreply, State, 0}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% Public API
%% @doc API for a module's function calls. Please note that all crashes should be handled at the
%% lowest level of the API (ex. erldns_storage_json).

%% @doc Call to a module's create. Creates a new table.
-spec create(atom()) -> ok.
create(Table) ->
    Module = mod(Table),
    Module:create(Table).

%% @doc Call to a module's insert. Inserts a value into the table.
-spec insert(atom(), tuple()) -> ok.
insert(Table, Value)->
    Module = mod(Table),
    Module:insert(Table, Value).

%% @doc Call to a module's delete_table. Deletes the entire table.
-spec delete_table(atom()) -> true.
delete_table(Table)->
    Module = mod(Table),
    Module:delete_table(Table).

%% @doc Call to a module's delete. Deletes a key value from a table.
-spec delete(atom(), term()) -> true.
delete(Table, Key) ->
    Module = mod(Table),
    Module:delete(Table, Key).

%% @doc Backup the table to the JSON file.
-spec backup_table(atom()) -> ok | {error, Reason :: term()}.
backup_table(Table)->
    Module = mod(Table),
    Module:backup_table(Table).

%% @doc Backup the tables to the JSON file.
-spec backup_tables() -> ok | {error, Reason :: term()}.
backup_tables() ->
    Module = mod(),
    Module:backup_tables().

%% @doc Call to a module's select. Uses table key pair, and can be considered a "lookup" in terms of ets.
-spec select(atom(), term()) -> tuple().
select(Table, Key) ->
    Module = mod(Table),
    Module:select(Table, Key).

%% @doc Call to a module's select. Uses a matchspec to generate matches.
-spec select(atom(), list(), integer()) -> tuple() | '$end_of_table'.
select(Table, MatchSpec, Limit) ->
    Module = mod(Table),
    Module:select(Table, MatchSpec, Limit).

%% @doc Call to a module's foldl.
-spec foldl(fun(), list(), atom())  -> Acc :: term() | {error, Reason :: term()}.
foldl(Fun, Acc, Table) ->
    Module = mod(Table),
    Module:foldl(Fun, Acc, Table).

%% @doc This function emptys the specified table of all values.
-spec empty_table(atom()) -> ok.
empty_table(Table) ->
    Module = mod(Table),
    Module:empty_table(Table).

%% @doc Load zones from a file. The default file name is "zones.json".
-spec load_zones() -> {ok, integer()} | {err,  atom()}.
load_zones() ->
    load_zones(filename()).

%% @doc Load zones from a file. The default file name is "zones.json".
-spec load_zones(list()) -> {ok, integer()} | {err,  atom()}.
load_zones(Filename) when is_list(Filename) ->
    case file:read_file(Filename) of
        {ok, Binary} ->
            lager:info("Parsing zones JSON"),
            JsonZones = jsx:decode(Binary),
            lager:info("Putting zones into cache"),
            lists:foreach(
                fun(JsonZone) ->
                    Zone = erldns_zone_parser:zone_to_erlang(JsonZone),
                    erldns_zone_cache:put_zone(Zone)
                end, JsonZones),
            lager:info("Loaded ~p zones", [length(JsonZones)]),
            {ok, length(JsonZones)};
        {error, Reason} ->
            lager:error("Failed to load zones: ~p", [Reason]),
            {err, Reason}
    end.

% Internal API
filename() ->
    case application:get_env(erldns, zones) of
        {ok, Filename} -> Filename;
        _ -> ?FILENAME
    end.

%% @doc This function retrieves the module name to be used for a given application or table (ex. erldns_storage_json...)
%% Matched tables are always going to use ets because they are either cached, or functionality
%% is optimal in ets.
mod() ->
    erldns_config:storage_type().

mod(packet_cache) ->
    erldns_storage_json;
mod(host_throttle) ->
    erldns_storage_json;
mod(handler_registry) ->
    erldns_storage_json;
mod(_Table) ->
    erldns_config:storage_type().

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("erldns.hrl").
-include("../deps/dns/include/dns.hrl").
-endif.

-ifdef(TEST).
    mnesia_test() ->
        application:set_env(erldns, storage, [{type, erldns_storage_mnesia}]),
        erldns_storage_mnesia = erldns_config:storage_type(),
        DNSRR = #dns_rr{name = <<"TEST DNSRR NAME">>, class = 1, type = 0, ttl = 0, data = <<"TEST DNSRR DATA">>},
        ZONE1 = #zone{name = <<"TEST NAME 1">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
        ZONE2 = #zone{name = <<"TEST NAME 2">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
        ZONE3 = #zone{name = <<"TEST NAME 3">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
        ZONE4 = #zone{name = <<"TEST NAME 4">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
        ZONE5 = #zone{name = <<"TEST NAME 5">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
        create(schema),
        create(zones),
        mnesia:wait_for_tables([zones], 10000),
        insert(zones, ZONE1),
        insert(zones, ZONE2),
        insert(zones, ZONE3),
        insert(zones, {<<"Test Name">>, ZONE4}),
        insert(zones, {<<"Test Name">>, ZONE5}),
        backup_table(zones),
        %%Iterate through table and see all the entrys.
        Iterator =  fun(Rec,_)->
            io:format("~p~n",[Rec]),
            []
        end,
        foldl(Iterator, [], zones),
        select(zones, <<"TEST NAME 1">>),
        delete(zones, <<"TEST NAME 1">>),
        empty_table(zones),
        delete_table(zones),
        %%authority test
        create(authorities),
        mnesia:wait_for_tables([authorities], 10000),
        AUTH1 = #authorities{owner_name = <<"Test Name">>, ttl = 1, class = <<"test calss">>, name_server = <<"Test Name Server">>,
                             email_addr = <<"test email">>, serial_num = 1, refresh = 1, retry = 1, expiry = 1, nxdomain = <<"test domain">>},
        AUTH2 = #authorities{owner_name = <<"Test Name">>, ttl = 1, class = <<"test calss">>, name_server = <<"Test Name Server">>,
                             email_addr = <<"test email">>, serial_num = 1, refresh = 1, retry = 1, expiry = 1, nxdomain = <<"test domain">>},
        AUTH3 = #authorities{owner_name = <<"Test Name">>, ttl = 1, class = <<"test calss">>, name_server = <<"Test Name Server">>,
                             email_addr = <<"test email">>, serial_num = 1, refresh = 1, retry = 1, expiry = 1, nxdomain = <<"test domain">>},
        insert(authorities, AUTH1),
        insert(authorities, AUTH2),
        insert(authorities, AUTH3),
        backup_table(authorities),
        foldl(Iterator, [], authorities),
        select(authorities, <<"Test Name">>),
        delete(authorities, <<"Test Name">>),
        empty_table(authorities),
        delete_table(authorities).

json_test() ->
    application:set_env(erldns, storage, [{type, erldns_storage_json}]),
    erldns_storage_json = erldns_config:storage_type(),
    DNSRR = #dns_rr{name = <<"TEST DNSRR NAME">>, class = 1, type = 0, ttl = 0, data = <<"TEST DNSRR DATA">>},
    ZONE1 = #zone{name = <<"TEST NAME 1">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE2 = #zone{name = <<"TEST NAME 2">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE3 = #zone{name = <<"TEST NAME 3">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE4 = #zone{name = <<"TEST NAME 4">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    ZONE5 = #zone{name = <<"TEST NAME 5">>, version = <<"1">>,authority =  [], record_count = 0, records = [], records_by_name = DNSRR, records_by_type = DNSRR},
    create(zones),
    insert(zones, ZONE1),
    insert(zones, ZONE2),
    insert(zones, ZONE3),
    insert(zones, ZONE4),
    insert(zones, ZONE5),
    backup_table(zones),
    %%Iterate through table and see all the entrys.
    Iterator =  fun(Rec,_)->
        io:format("~p~n",[Rec]),
        []
    end,
    foldl(Iterator, [], zones),
    select(zones, <<"TEST NAME 1">>),
    delete(zones, <<"TEST NAME 1">>),
    empty_table(zones),
    delete_table(zones).
    -endif.
