%% Copyright (c) 2012-2015, Aetrion LLC
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

%% Functions related to DNS records.
-module(erldns_records).

-include("erldns.hrl").
-include_lib("dns/include/dns.hrl").
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([wildcard_qname/1]).
-export([wildcard_substitution/2, dname_match/2]).
-export([default_ttl/1, default_priority/1, name_type/1, root_hints/0]).
-export([minimum_soa_ttl/2]).
-export([match_name/1, match_type/1, match_name_and_type/2, match_types/1, match_wildcard/0, match_delegation/1]).
-export([replace_name/1]).
-export([match_glue/1, match_dnskey_type/1, match_optrr/0, match_any_subdomain/1]).
-export([not_match/1]).
-export([empty_name_predicate/0]).
-export([rr_to_name/0]).
-export([records_to_rrsets/1]).

%% @doc Get a wildcard variation of a Qname. Replaces the leading
%% label with an asterisk for wildcard lookup.
-spec wildcard_qname(dns:dname()) -> dns:dname().
wildcard_qname(Qname) ->
  [_|Rest] = dns:dname_to_labels(Qname),
  dns:labels_to_dname([<<"*">>] ++ Rest).


%% @doc If the first argument is a wildcard name, and the second matches
%% that wildcard name, substitute the Qname for the wildcard name.
-spec wildcard_substitution(dns:dname(), dns:dname()) -> dns:dname().
wildcard_substitution(Name, Qname) ->
  case dname_match(Qname, Name) of
    true -> Qname;
    false -> Name
  end.
-ifdef(TEST).

wildcard_substitution_test_() ->
  Qname = <<"a.a1.example.com">>,
  [
   ?_assert(wildcard_substitution(<<"a.a1.example.com">>, Qname) =:= <<"a.a1.example.com">>),
   ?_assert(wildcard_substitution(<<"*.a1.example.com">>, Qname) =:= Qname),
   ?_assert(wildcard_substitution(<<"*.b1.example.com">>, Qname) =:= <<"*.b1.example.com">>)
  ].
-endif.



% @doc Return true if the names match with wildcard substitution.
%
% N2 must always be the wildcard.
-spec dname_match(dns:dname(), dns:dname()) -> boolean().
dname_match(N1, N2) ->
  %lager:debug("dname_match(~p, ~p)", [N1, N2]),
  case length(dns:dname_to_labels(N1)) < length(dns:dname_to_labels(N2)) of
    true -> false;
    false ->
      L1 = strip_wildcard(N1),
      L2 = strip_wildcard(N2),
      L2R = remove_labels(N1, L1, L2),
      L1R = remove_labels(N2, L2, L1),
      L1R =:= L2R
  end.

-ifdef(TEST).
dname_match_test_() ->
  [
   ?_assert(dname_match(<<"a.a1.example.com">>, <<"a.a1.example.com">>)),
   ?_assert(dname_match(<<"a.a1.example.com">>, <<"*.a1.example.com">>)),
   ?_assertNot(dname_match(<<"a.a1.example.com">>, <<"a.b1.example.com">>)),
   ?_assertNot(dname_match(<<"a.a1.example.com">>, <<"*.b1.example.com">>)),
   ?_assertNot(dname_match(<<"a1.example.com">>, <<"*.a1.example.com">>))
  ].
-endif.


% @doc Convert a name into labels. Wildcards are removed.
-spec strip_wildcard(dns:dname()) -> [dns:label()].
strip_wildcard(Name) ->
  case lists:any(match_wildcard_label(), dns:dname_to_labels(Name)) of
    true ->lists:dropwhile(match_wildcard_label(), dns:dname_to_labels(Name));
    _ -> dns:dname_to_labels(Name)
  end.

-ifdef(TEST).
strip_wildcard_test_() ->
  [
    ?_assert(strip_wildcard(<<"a.a1.example.com">>) =:= dns:dname_to_labels(<<"a.a1.example.com">>)),
    ?_assert(strip_wildcard(<<"*.a1.example.com">>) =:= dns:dname_to_labels(<<"a1.example.com">>))
  ].
-endif.


%% @doc Given a name, and two different label lists, return the shared subdomain
%% from the label lists, if one exists. If there is no shared subdomain then 
%% return the second label list.
remove_labels(Name, L1, L2) ->
  case length(L1) =:= length(dns:dname_to_labels(Name)) of
    true -> L2;
    false -> lists:reverse(lists:sublist(lists:reverse(L2), length(L1)))
  end.

-ifdef(TEST).
remove_labels_test_() ->
  [
    ?_assert(remove_labels(<<"a.a1.example.com">>, dns:dname_to_labels(<<"a.a1.example.com">>), dns:dname_to_labels(<<"b.a1.example.com">>)) =:= dns:dname_to_labels(<<"b.a1.example.com">>)),
    ?_assert(remove_labels(<<"a.a1.example.com">>, dns:dname_to_labels(<<"a1.example.com">>), dns:dname_to_labels(<<"b.a1.example.com">>)) =:= dns:dname_to_labels(<<"a1.example.com">>)),
    ?_assert(remove_labels(<<"b.a.a1.example.com">>, dns:dname_to_labels(<<"a1.example.com">>), dns:dname_to_labels(<<"b.a.a1.example.com">>)) =:= dns:dname_to_labels(<<"a1.example.com">>))
  ].
-endif.


% @doc Return the TTL value or 3600 if it is undefined.
default_ttl(TTL) ->
  case TTL of
    undefined -> 3600;
    Value -> Value
  end.

%% @doc Return the Priority value or 0 if it is undefined.
default_priority(Priority) ->
  case Priority of
    undefined -> 0;
    Value -> Value
  end.

%% @doc Applies a minimum TTL based on the SOA minumum value.
%%
%% The first argument is the Record that is being updated.
%% The second argument is the SOA RR Data.
-spec minimum_soa_ttl(dns:dns_rr(), dns:dns_rrdata_soa()) -> dns:dns_rr().
minimum_soa_ttl(Record, Data) when is_record(Data, dns_rrdata_soa) -> Record#dns_rr{ttl = erlang:min(Data#dns_rrdata_soa.minimum, Record#dns_rr.ttl)};
minimum_soa_ttl(Record, _) -> Record.

%% @doc Takes a list of records of potentially different types
%% and returns a new list of lists, where each list contains
%% only a specific type.
-spec records_to_rrsets([dns:dns_rr()]) -> [[dns:dns_rr()],...].
records_to_rrsets(Records) ->
  RRSets = records_to_rrsets(Records, []),
  lists:map(fun({_Type, RRSet}) -> RRSet end, RRSets).

records_to_rrsets([], RRSets) -> RRSets;
records_to_rrsets([RR|Rest], RRSets) ->
  Type = RR#dns_rr.type,
  NewRRSets = case lists:keyfind(Type, 1, RRSets) of
                {Type, RRs} ->
                  lists:keyreplace(Type, 1, RRSets, {Type, RRs ++ [RR]});
                false ->
                  lists:keystore(Type, 1, RRSets, {Type, [RR]})
              end,
  records_to_rrsets(Rest, NewRRSets).

-ifdef(TEST).
records_to_rrsets_test_() ->
  [
    ?_assertEqual(records_to_rrsets([]), []),
    ?_assertEqual(records_to_rrsets([#dns_rr{type = ?DNS_TYPE_A}]), [[#dns_rr{type = ?DNS_TYPE_A}]]),
    ?_assertEqual(records_to_rrsets([#dns_rr{type = ?DNS_TYPE_A}, #dns_rr{type = ?DNS_TYPE_NS}]), [[#dns_rr{type = ?DNS_TYPE_A}], [#dns_rr{type = ?DNS_TYPE_NS}]]),
    ?_assertEqual(records_to_rrsets([#dns_rr{type = ?DNS_TYPE_A}, #dns_rr{type = ?DNS_TYPE_NS}, #dns_rr{type = ?DNS_TYPE_A}]), [[#dns_rr{type = ?DNS_TYPE_A}, #dns_rr{type = ?DNS_TYPE_A}], [#dns_rr{type = ?DNS_TYPE_NS}]]),
    ?_assertNotEqual(records_to_rrsets([#dns_rr{type = ?DNS_TYPE_A}]), [])
  ].
-endif.


%% Various matching functions.
match_name(Name) ->
  fun(R) when is_record(R, dns_rr) ->
      R#dns_rr.name =:= Name
  end.

match_type(Type) ->
  fun(R) when is_record(R, dns_rr) ->
      R#dns_rr.type =:= Type
  end.

match_name_and_type(Name, Type) ->
  fun(R) when is_record(R, dns_rr) ->
      (R#dns_rr.name =:= Name) and (R#dns_rr.type =:= Type)
  end.

match_types(Types) ->
  fun(R) when is_record(R, dns_rr) ->
      lists:any(fun(T) -> R#dns_rr.type =:= T end, Types)
  end.

match_wildcard() ->
  fun(R) when is_record(R, dns_rr) ->
      lists:any(match_wildcard_label(), dns:dname_to_labels(R#dns_rr.name))
  end.

match_wildcard_label() ->
  fun(L) ->
      L =:= <<"*">>
  end.

match_delegation(Name) ->
  fun(R) when is_record(R, dns_rr) ->
      R#dns_rr.data =:= #dns_rrdata_ns{dname=Name}
  end.

match_glue(Name) ->
  fun(R) when is_record(R, dns_rr) ->
    ((R#dns_rr.type =:= ?DNS_TYPE_A) or (R#dns_rr.type =:= ?DNS_TYPE_AAAA)) and (R#dns_rr.name =:= Name)
  end.

match_dnskey_type(Type) ->
  fun (R) when is_record(R, dns_rr) ->
      case R#dns_rr.data of
        D when is_record(D, dns_rrdata_dnskey) -> R#dns_rr.data#dns_rrdata_dnskey.flags =:= Type;
        _ -> false
      end
  end.

match_optrr() ->
  fun(R) ->
      case R of
        _ when is_record(R, dns_optrr) -> true;
        _ -> false
      end
  end.

match_any_subdomain(Name) ->
  fun(R) ->
      is_subdomain(Name, R#dns_rr.name)
  end.

not_match(F) ->
  fun(R) ->
      not(F(R))
  end.

empty_name_predicate() ->
  fun(R) ->
      R#dns_rr.name =/= <<"">>
  end.


rr_to_name() ->
  fun(R) ->
      R#dns_rr.name
  end.


%% Replacement functions.
replace_name(Name) -> fun(R) when is_record(R, dns_rr) -> R#dns_rr{name = Name} end.

%% @doc Return true if the OtherLabels is a subdomain of Labels.
-spec is_subdomain(dns:dname(), dns:dname()) -> boolean().
is_subdomain(Name, OtherName) when is_bitstring(Name) and is_bitstring(OtherName) ->
  IsSubdomain = is_subdomain(lists:reverse(dns:dname_to_labels(Name)), lists:reverse(dns:dname_to_labels(OtherName))),
  %lager:debug("Is ~p a subdomain of ~p? ~p", [OtherName, Name, IsSubdomain]),
  IsSubdomain;
is_subdomain([], []) ->
  false;
is_subdomain([], _OtherLabels) ->
  true;
is_subdomain(_Labels, []) ->
  false;
is_subdomain([L|Rest], [OL|ORest]) ->
  case L =:= OL of
    true -> is_subdomain(Rest, ORest);
    false -> false
  end.

-ifdef(TEST).
is_subdomain_test_() ->
  [
    ?_assertNot(is_subdomain(<<"example.com">>, <<"example.com">>)),
    ?_assertNot(is_subdomain(<<"example.com">>, <<"example.net">>)),
    ?_assertNot(is_subdomain(<<"example.com">>, <<"www.example.com.net">>)),
    ?_assert(is_subdomain(<<"example.com">>, <<"www.example.com">>)),
    ?_assert(is_subdomain(<<"example.com">>, <<"a.b.c.example.com">>)),
    ?_assert(is_subdomain(<<"example.com">>, <<"*.a.b.c.example.com">>))
  ].
-endif.


%% @doc Returns the type value given a binary string.
-spec name_type(binary()) -> dns:type() | 'undefined'.
name_type(Type) when is_binary(Type) ->
  case Type of
    ?DNS_TYPE_A_BSTR -> ?DNS_TYPE_A_NUMBER;
    ?DNS_TYPE_NS_BSTR -> ?DNS_TYPE_NS_NUMBER;
    ?DNS_TYPE_MD_BSTR -> ?DNS_TYPE_MD_NUMBER;
    ?DNS_TYPE_MF_BSTR -> ?DNS_TYPE_MF_NUMBER;
    ?DNS_TYPE_CNAME_BSTR -> ?DNS_TYPE_CNAME_NUMBER;
    ?DNS_TYPE_SOA_BSTR -> ?DNS_TYPE_SOA_NUMBER;
    ?DNS_TYPE_MB_BSTR -> ?DNS_TYPE_MB_NUMBER;
    ?DNS_TYPE_MG_BSTR -> ?DNS_TYPE_MG_NUMBER;
    ?DNS_TYPE_MR_BSTR -> ?DNS_TYPE_MR_NUMBER;
    ?DNS_TYPE_NULL_BSTR -> ?DNS_TYPE_NULL_NUMBER;
    ?DNS_TYPE_WKS_BSTR -> ?DNS_TYPE_WKS_NUMBER;
    ?DNS_TYPE_PTR_BSTR -> ?DNS_TYPE_PTR_NUMBER;
    ?DNS_TYPE_HINFO_BSTR -> ?DNS_TYPE_HINFO_NUMBER;
    ?DNS_TYPE_MINFO_BSTR -> ?DNS_TYPE_MINFO_NUMBER;
    ?DNS_TYPE_MX_BSTR -> ?DNS_TYPE_MX_NUMBER;
    ?DNS_TYPE_TXT_BSTR -> ?DNS_TYPE_TXT_NUMBER;
    ?DNS_TYPE_RP_BSTR -> ?DNS_TYPE_RP_NUMBER;
    ?DNS_TYPE_AFSDB_BSTR -> ?DNS_TYPE_AFSDB_NUMBER;
    ?DNS_TYPE_X25_BSTR -> ?DNS_TYPE_X25_NUMBER;
    ?DNS_TYPE_ISDN_BSTR -> ?DNS_TYPE_ISDN_NUMBER;
    ?DNS_TYPE_RT_BSTR -> ?DNS_TYPE_RT_NUMBER;
    ?DNS_TYPE_NSAP_BSTR -> ?DNS_TYPE_NSAP_NUMBER;
    ?DNS_TYPE_SIG_BSTR -> ?DNS_TYPE_SIG_NUMBER;
    ?DNS_TYPE_KEY_BSTR -> ?DNS_TYPE_KEY_NUMBER;
    ?DNS_TYPE_PX_BSTR -> ?DNS_TYPE_PX_NUMBER;
    ?DNS_TYPE_GPOS_BSTR -> ?DNS_TYPE_GPOS_NUMBER;
    ?DNS_TYPE_AAAA_BSTR -> ?DNS_TYPE_AAAA_NUMBER;
    ?DNS_TYPE_LOC_BSTR -> ?DNS_TYPE_LOC_NUMBER;
    ?DNS_TYPE_NXT_BSTR -> ?DNS_TYPE_NXT_NUMBER;
    ?DNS_TYPE_EID_BSTR -> ?DNS_TYPE_EID_NUMBER;
    ?DNS_TYPE_NIMLOC_BSTR -> ?DNS_TYPE_NIMLOC_NUMBER;
    ?DNS_TYPE_SRV_BSTR -> ?DNS_TYPE_SRV_NUMBER;
    ?DNS_TYPE_ATMA_BSTR -> ?DNS_TYPE_ATMA_NUMBER;
    ?DNS_TYPE_NAPTR_BSTR -> ?DNS_TYPE_NAPTR_NUMBER;
    ?DNS_TYPE_KX_BSTR -> ?DNS_TYPE_KX_NUMBER;
    ?DNS_TYPE_CERT_BSTR -> ?DNS_TYPE_CERT_NUMBER;
    ?DNS_TYPE_DNAME_BSTR -> ?DNS_TYPE_DNAME_NUMBER;
    ?DNS_TYPE_SINK_BSTR -> ?DNS_TYPE_SINK_NUMBER;
    ?DNS_TYPE_OPT_BSTR -> ?DNS_TYPE_OPT_NUMBER;
    ?DNS_TYPE_APL_BSTR -> ?DNS_TYPE_APL_NUMBER;
    ?DNS_TYPE_DS_BSTR -> ?DNS_TYPE_DS_NUMBER;
    ?DNS_TYPE_SSHFP_BSTR -> ?DNS_TYPE_SSHFP_NUMBER;
    ?DNS_TYPE_IPSECKEY_BSTR -> ?DNS_TYPE_IPSECKEY_NUMBER;
    ?DNS_TYPE_RRSIG_BSTR -> ?DNS_TYPE_RRSIG_NUMBER;
    ?DNS_TYPE_NSEC_BSTR -> ?DNS_TYPE_NSEC_NUMBER;
    ?DNS_TYPE_DNSKEY_BSTR -> ?DNS_TYPE_DNSKEY_NUMBER;
    ?DNS_TYPE_NSEC3_BSTR -> ?DNS_TYPE_NSEC3_NUMBER;
    ?DNS_TYPE_NSEC3PARAM_BSTR -> ?DNS_TYPE_NSEC3PARAM_NUMBER;
    ?DNS_TYPE_DHCID_BSTR -> ?DNS_TYPE_DHCID_NUMBER;
    ?DNS_TYPE_HIP_BSTR -> ?DNS_TYPE_HIP_NUMBER;
    ?DNS_TYPE_NINFO_BSTR -> ?DNS_TYPE_NINFO_NUMBER;
    ?DNS_TYPE_RKEY_BSTR -> ?DNS_TYPE_RKEY_NUMBER;
    ?DNS_TYPE_TALINK_BSTR -> ?DNS_TYPE_TALINK_NUMBER;
    ?DNS_TYPE_SPF_BSTR -> ?DNS_TYPE_SPF_NUMBER;
    ?DNS_TYPE_UINFO_BSTR -> ?DNS_TYPE_UINFO_NUMBER;
    ?DNS_TYPE_UID_BSTR -> ?DNS_TYPE_UID_NUMBER;
    ?DNS_TYPE_GID_BSTR -> ?DNS_TYPE_GID_NUMBER;
    ?DNS_TYPE_UNSPEC_BSTR -> ?DNS_TYPE_UNSPEC_NUMBER;
    ?DNS_TYPE_TKEY_BSTR -> ?DNS_TYPE_TKEY_NUMBER;
    ?DNS_TYPE_TSIG_BSTR -> ?DNS_TYPE_TSIG_NUMBER;
    ?DNS_TYPE_IXFR_BSTR -> ?DNS_TYPE_IXFR_NUMBER;
    ?DNS_TYPE_AXFR_BSTR -> ?DNS_TYPE_AXFR_NUMBER;
    ?DNS_TYPE_MAILB_BSTR -> ?DNS_TYPE_MAILB_NUMBER;
    ?DNS_TYPE_MAILA_BSTR -> ?DNS_TYPE_MAILA_NUMBER;
    ?DNS_TYPE_ANY_BSTR -> ?DNS_TYPE_ANY_NUMBER;
    ?DNS_TYPE_DLV_BSTR -> ?DNS_TYPE_DLV_NUMBER;
    _ -> undefined
  end.

root_hints() ->
  {
   [
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"a.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"b.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"c.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"d.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"e.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"f.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"g.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"h.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"i.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"j.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"k.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"l.root-servers.net">>}},
    #dns_rr{name = <<"">>, type=?DNS_TYPE_NS, ttl=518400, data = #dns_rrdata_ns{dname = <<"m.root-servers.net">>}}
   ],
   [
    #dns_rr{name = <<"a.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {198,41,0,4}}},
    #dns_rr{name = <<"b.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,228,79,201}}},
    #dns_rr{name = <<"c.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,33,4,12}}},
    #dns_rr{name = <<"d.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {128,8,10,90}}},
    #dns_rr{name = <<"e.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,203,230,10}}},
    #dns_rr{name = <<"f.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,5,5,241}}},
    #dns_rr{name = <<"g.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,112,36,4}}},
    #dns_rr{name = <<"h.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {128,63,2,53}}},
    #dns_rr{name = <<"i.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,36,148,17}}},
    #dns_rr{name = <<"j.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {192,58,128,30}}},
    #dns_rr{name = <<"k.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {193,0,14,129}}},
    #dns_rr{name = <<"l.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {198,32,64,12}}},
    #dns_rr{name = <<"m.root-servers.net">>, type=?DNS_TYPE_A, ttl=3600000, data = #dns_rrdata_a{ip = {202,12,27,33}}}
   ]
  }.



-ifdef(TEST).

wildcard_qname_test_() ->
  ?_assertEqual(<<"*.b.example.com">>, wildcard_qname(<<"a.b.example.com">>)).

minimum_soa_ttl_test_() ->
  [
    ?_assertMatch(#dns_rr{ttl = 3600}, minimum_soa_ttl(#dns_rr{ttl = 3600}, #dns_rrdata_a{})),
    ?_assertMatch(#dns_rr{ttl = 30}, minimum_soa_ttl(#dns_rr{ttl = 3600}, #dns_rrdata_soa{minimum = 30})),
    ?_assertMatch(#dns_rr{ttl = 30}, minimum_soa_ttl(#dns_rr{ttl = 30}, #dns_rrdata_soa{minimum = 3600}))
  ].

replace_name_test_() ->
  [
   ?_assertEqual([], lists:map(replace_name(<<"example">>), [])),
   ?_assertMatch([#dns_rr{name = <<"example">>}], lists:map(replace_name(<<"example">>), [#dns_rr{name = <<"test.com">>}]))
  ].

match_name_test_() ->
  [
    ?_assert(lists:any(match_name(<<"example.com">>), [#dns_rr{name = <<"example.com">>}])),
    ?_assertNot(lists:any(match_name(<<"example.com">>), [#dns_rr{name = <<"example.net">>}]))
  ].

match_type_test_() ->
  [
    ?_assert(lists:any(match_type(?DNS_TYPE_A), [#dns_rr{type = ?DNS_TYPE_A}])),
    ?_assertNot(lists:any(match_type(?DNS_TYPE_CNAME), [#dns_rr{type = ?DNS_TYPE_A}]))
  ].

match_types_test_() ->
  [
    ?_assert(lists:any(match_types([?DNS_TYPE_A]), [#dns_rr{type = ?DNS_TYPE_A}])),
    ?_assert(lists:any(match_types([?DNS_TYPE_A, ?DNS_TYPE_CNAME]), [#dns_rr{type = ?DNS_TYPE_A}])),
    ?_assertNot(lists:any(match_types([?DNS_TYPE_CNAME]), [#dns_rr{type = ?DNS_TYPE_A}]))
  ].

match_wildcard_test_() ->
  [
    ?_assert(lists:any(match_wildcard(), [#dns_rr{name = <<"*.example.com">>}])),
    ?_assertNot(lists:any(match_wildcard(), [#dns_rr{name = <<"www.example.com">>}]))
  ].

match_delegation_test_() ->
  [
    ?_assert(lists:any(match_delegation(<<"ns1.example.com">>), [#dns_rr{data = #dns_rrdata_ns{dname = <<"ns1.example.com">>}}])),
    ?_assertNot(lists:any(match_delegation(<<"ns1.example.com">>), [#dns_rr{data = #dns_rrdata_ns{dname = <<"ns2.example.com">>}}]))
  ].

match_glue_test_() ->
  [
    ?_assert(lists:any(match_glue(<<"ns1.example.com">>), [#dns_rr{name = <<"ns1.example.com">>, type = ?DNS_TYPE_A}])),
    ?_assert(lists:any(match_glue(<<"ns1.example.com">>), [#dns_rr{name = <<"ns1.example.com">>, type = ?DNS_TYPE_AAAA}])),
    ?_assertNot(lists:any(match_glue(<<"ns1.example.com">>), [#dns_rr{name = <<"ns1.example.com">>, type = ?DNS_TYPE_TXT}])),
    ?_assertNot(lists:any(match_glue(<<"ns1.example.com">>), [#dns_rr{name = <<"ns2.example.com">>, type = ?DNS_TYPE_A}]))
  ].

match_glue_dnskey_type_test_() ->
  [
    ?_assert(lists:any(match_dnskey_type(?DNSKEY_KSK_TYPE), [#dns_rr{data = #dns_rrdata_dnskey{flags = ?DNSKEY_KSK_TYPE}}])),
    ?_assert(lists:any(match_dnskey_type(?DNSKEY_ZSK_TYPE), [#dns_rr{data = #dns_rrdata_dnskey{flags = ?DNSKEY_ZSK_TYPE}}])),
    ?_assertNot(lists:any(match_dnskey_type(?DNSKEY_ZSK_TYPE), [#dns_rr{data = #dns_rrdata_dnskey{flags = ?DNSKEY_KSK_TYPE}}])),
    ?_assertNot(lists:any(match_dnskey_type(?DNSKEY_KSK_TYPE), [#dns_rr{data = #dns_rrdata_dnskey{flags = ?DNSKEY_ZSK_TYPE}}]))
  ].

match_optrr_test_() ->
  [
    ?_assert(lists:any(match_optrr(), [#dns_optrr{}])),
    ?_assertNot(lists:any(match_optrr(), [#dns_rr{}]))
  ].

match_wildcard_label_test_() ->
  [
    ?_assert(lists:any(match_wildcard_label(), dns:dname_to_labels(<<"*.example.com">>))),
    ?_assertNot(lists:any(match_wildcard_label(), dns:dname_to_labels(<<"www.example.com">>)))
  ].

match_any_subdomain_test_() ->
  [
    ?_assertNot(lists:any(match_any_subdomain(<<"example.com">>), [#dns_rr{name = <<"example.com">>}])),
    ?_assert(lists:any(match_any_subdomain(<<"example.com">>), [#dns_rr{name = <<"www.example.com">>}]))
  ].

not_match_test_() ->
  [
    ?_assertNot(lists:any(not_match(match_name(<<"name">>)), [#dns_rr{name = <<"name">>}])),
    ?_assert(lists:any(not_match(match_name(<<"name">>)), [#dns_rr{name = <<"notname">>}]))
  ].

-endif.
