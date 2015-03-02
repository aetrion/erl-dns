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

%% @doc Resolve a DNS query.
-module(erldns_resolver).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([resolve/3]).
-export([best_match/2]).

%% @doc Resolve the questions in the message.
-spec resolve(dns:message(), [dns:rr()], dns:ip()) -> dns:message().
resolve(Message, AuthorityRecords, Host) ->
  resolve(Message, AuthorityRecords, Host, Message#dns_message.questions).


%% There were no questions in the message so just return it.
-spec resolve(dns:message(), [dns:rr()], dns:ip(), [dns:question()]) -> dns:message().
resolve(Message, _AuthorityRecords, _Host, []) -> Message;
%% There is one question in the message; resolve it.
resolve(Message, AuthorityRecords, Host, [Question]) -> resolve(Message, AuthorityRecords, Host, Question);
%% Resolve the first question. Additional questions will be thrown away for now.
resolve(Message, AuthorityRecords, Host, [Question|_]) -> resolve(Message, AuthorityRecords, Host, Question);

%% Start the resolution process on the given question.
%% Step 1: Set the RA bit to false as we do not handle recursive queries.
resolve(Message, AuthorityRecords, Host, Question) when is_record(Question, dns_query) ->
  check_dnssec(Message, Host, Question),
  ResolvedMessage = resolve(Message#dns_message{ra = false, ad = false}, AuthorityRecords, Qname = Question#dns_query.name, Question#dns_query.type, Host),
  substitute_wildcards(ResolvedMessage, Qname).

%% With the extracted Qname and Qtype in hand, find the nearest zone
%% Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
resolve(Message, AuthorityRecords, Qname, Qtype, Host) ->
  Zone = erldns_zone_cache:find_zone(Qname, lists:last(AuthorityRecords)),
  ResolvedMessage = resolve(Message, Qname, Qtype, Zone, Host, _CnameChain = []),

  case is_dnssec(Message, Zone) of
    true ->
      additional_processing(rewrite_soa_ttl(erldns_dnssec_nsec:sort(erldns_dnssec_nsec:sign_nsec_records(ResolvedMessage, Zone))), Host, Zone);
    false ->
      additional_processing(rewrite_soa_ttl(ResolvedMessage), Host, Zone)
  end.

%% No SOA was found for the Qname so we return the root hints
%% Note: it seems odd that we are indicating we are authoritative here.
resolve(Message, _Qname, _Qtype, {error, not_authoritative}, _Host, _CnameChain) ->
  case erldns_config:use_root_hints() of
    true ->
      {Authority, Additional} = erldns_records:root_hints(),
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ Authority, additional = Message#dns_message.additional ++ Additional};
    _ ->
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR}
  end;

%% An SOA was found, thus we are authoritative, however the qtype is RRSIG.
resolve(Message, _Qname, ?DNS_TYPE_RRSIG, _Zone, _Host, _CnameChain) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOTIMP};

%% An SOA was found, thus we are authoritative, special handling for DS record.
resolve(Message, Qname, Qtype = ?DNS_TYPE_DS, Zone, Host, CnameChain) ->
  case is_dnssec(Message, Zone) of
    true ->
      % If we are at the apex, do not return a DS, get it from the parent if the parent is present
      case is_apex(Qname, Zone) of
        true ->
          Labels = dns:dname_to_labels(Qname),
          [_|ParentLabels] = Labels,
          ParentName = dns:labels_to_dname(ParentLabels),
          case erldns_zone_cache:get_zone_with_records(ParentName) of
            {ok, ParentZone} ->
              MatchedRecords = lists:filter(erldns_records:match_name_and_type(Qname, ?DNS_TYPE_DS), ParentZone#zone.records),
              resolve(Message, Qname, Qtype, MatchedRecords, Host, CnameChain, ParentZone);
            {error, _Reason} ->
              start_resolve(Message, Qname, Qtype, Zone, Host, CnameChain)
          end;
        false ->
          start_resolve(Message, Qname, Qtype, Zone, Host, CnameChain)
      end;
    false ->
      start_resolve(Message, Qname, Qtype, Zone, Host, CnameChain)
  end;

%% An SOA was found, thus we are authoritative and have the zone.
%% Step 3: Match records
resolve(Message, Qname, Qtype, Zone, Host, CnameChain) ->
  start_resolve(Message, Qname, Qtype, Zone, Host, CnameChain).

start_resolve(Message, Qname, Qtype, Zone, Host, CnameChain) ->
  case is_dnssec(Message, Zone) of
    true ->
      RecordsByName = case {Qtype, is_apex(Qname, Zone)} of
                        {?DNS_TYPE_ANY, true} ->
                          erldns_zone_cache:get_records_by_name(Qname) ++ erldns_dnssec:dnskey_rrset(Message, Zone);
                        _ ->
                          erldns_zone_cache:get_records_by_name(Qname)
                      end,
      ResolvedMessage = resolve(Message, Qname, Qtype, RecordsByName, Host, CnameChain, Zone),
      {ok, ZoneWithRecords} = erldns_zone_cache:get_zone_with_records(Zone#zone.name),
      erldns_dnssec_nsec_simple:include_nsec(ResolvedMessage, Qname, Qtype, ZoneWithRecords, CnameChain);
    false ->
      resolve(Message, Qname, Qtype, erldns_zone_cache:get_records_by_name(Qname), Host, CnameChain, Zone)
  end.

%% There were no exact matches on name, so move to the best-match resolution.
resolve(Message, Qname, Qtype, _MatchedRecords = [], Host, CnameChain, Zone) ->
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, best_match(Qname, Zone), Zone);

%% There was at least one exact match on name.
resolve(Message, Qname, Qtype, MatchedRecords, Host, CnameChain, Zone) ->
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone).



%% Determine if there is a CNAME anywhere in the records with the given Qname.
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  CnameRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), MatchedRecords), % Query record set for CNAME type
  exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).

%% No CNAME records found in the records with the Qname
exact_match_resolution(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _CnameRecords = []) ->
  resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone);

%% CNAME records found in the records for the Qname
exact_match_resolution(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords).




%% There were no CNAMEs found in the exact name matches, so now we grab the authority
%% records and find any type matches on QTYPE and continue on.
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone) ->
  AuthorityRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), MatchedRecords),
  TypeMatches = case {Qtype, is_apex(Qname, Zone)} of
                  {?DNS_TYPE_ANY, _} ->
                    filter_records(MatchedRecords, erldns_handler:get_handlers());
                  {?DNS_TYPE_DNSKEY, true} ->
                    erldns_dnssec:dnskey_rrset(Message, Zone);
                  _ ->
                    lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
                end,
  case TypeMatches of
    [] ->
      %% Ask the custom handlers for their records.
      NewRecords = lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords), erldns_handler:get_handlers())),
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, NewRecords, AuthorityRecords);
    _ ->
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, TypeMatches, AuthorityRecords)
  end.

%% There were no matches for exact name and type, so now we are looking for NS records
%% in the exact name matches.
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _ExactTypeMatches = [], AuthorityRecords) ->
  ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), MatchedRecords), % Query matched records for NS type
  resolve_no_exact_type_match(Message, Qname, Qtype, Host, CnameChain, [], Zone, MatchedRecords, ReferralRecords, AuthorityRecords);

%% There were exact matches of name and type.
resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, _MatchedRecords, Zone, ExactTypeMatches, AuthorityRecords) ->
  resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, ExactTypeMatches, Zone, AuthorityRecords).



%% There was an exact type match for an NS query, however there is no SOA record for the zone.
resolve_exact_type_match(Message, _Qname, ?DNS_TYPE_NS, Host, CnameChain, MatchedRecords, Zone, []) ->
  Answer = lists:last(MatchedRecords),
  Name = Answer#dns_rr.name,
  % It isn't clear what the QTYPE should be on a delegated restart. I assume an A record.
  restart_delegated_query(Message, Name, ?DNS_TYPE_A, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));

%% There was an exact type match for an NS query and an SOA record.
resolve_exact_type_match(Message, _Qname, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, Zone, _AuthorityRecords) ->
  case is_dnssec(Message, Zone) of
    true ->
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = erldns_dnssec:sign_records(Message, Zone, MatchedRecords)};
    false ->
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = MatchedRecords}
  end;

%% There was an exact type match for something other than an NS record and we are authoritative because there is an SOA record.
resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords) ->
  % NOTE: this is a potential bug because it assumes the last record is the one to examine.
  Answer = lists:last(MatchedRecords),
  case DelegationRecords = erldns_zone_cache:get_delegations(Answer#dns_rr.name) of
    [] ->
      resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, DelegationRecords);
    _ ->
      DelegationRecord = lists:last(DelegationRecords),
      case erldns_zone_cache:get_authority(Qname) of
        {ok, [SoaRecord]} ->
          case SoaRecord#dns_rr.name =:= DelegationRecord#dns_rr.name of
            true ->
              resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, []);
            false ->
              resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, DelegationRecords)
          end;
        {error, authority_not_found} ->
          resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, DelegationRecords)
      end
  end.

%% We are authoritative and not delegating.
resolve_exact_type_match(Message, _Qname, _Qtype, _Host, _CnameChain, MatchedRecords, Zone, _AuthorityRecords, _DelegationRecords = []) ->
  case is_dnssec(Message, Zone) of
    true ->
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = erldns_dnssec:sign_records(Message, Zone, MatchedRecords)};
    false ->
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords}
  end;

%% We are authoritative and there are delegation records here.
resolve_exact_type_match(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, DelegationRecords) ->
  % NOTE: there are potential bugs here because it assumes the last record is the one to examine
  Answer = lists:last(MatchedRecords),
  DelegationRecord = lists:last(DelegationRecords),
  Name = DelegationRecord#dns_rr.name,
  case Name =:= Answer#dns_rr.name of
    true -> % Handle NS recursion breakout
      Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ DelegationRecords};
    false ->
      % TODO: only restart delegation if the NS record is on a parent node
      % if it is a sibling then we should not restart
      case check_if_parent(Name, Answer#dns_rr.name) of
        true ->
          restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));
        false ->
          Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords}
      end
  end.

%% Returns true if the first domain name is a parent of the second domain name.
check_if_parent(PossibleParentName, Name) ->
  case lists:subtract(dns:dname_to_labels(PossibleParentName), dns:dname_to_labels(Name)) of
    [] -> true;
    _ -> false
  end.


%% There were no exact type matches, but there were other name matches and there are NS records.
%% Since the Qtype is ANY we indicate we are authoritative and include the NS records.
resolve_no_exact_type_match(Message, _Qname, ?DNS_TYPE_ANY, _Host, _CnameChain, _ExactTypeMatches, _Zone, _MatchedRecords = [], _ReferralRecords = [], AuthorityRecords) ->
  Message#dns_message{aa = true, authority = AuthorityRecords};
resolve_no_exact_type_match(Message, Qname, Qtype, _Host, _CnameChain, _ExactTypeMatches = [], Zone, _MatchedRecords, _ReferralRecords = [], _AuthorityRecords) ->
  ResolvedMessage = Message#dns_message{aa = true, authority = Message#dns_message.authority ++ Zone#zone.authority},
  sign_records(ResolvedMessage, Qname, Qtype, Zone, [], Zone#zone.authority);
resolve_no_exact_type_match(Message, Qname, Qtype, _Host, _CnameChain, ExactTypeMatches, Zone, _MatchedRecords, _ReferralRecords = [], AuthorityRecords) ->
  ResolvedMessage = Message#dns_message{aa = true, answers = Message#dns_message.answers ++ ExactTypeMatches},
  sign_records(ResolvedMessage, Qname, Qtype, Zone, ExactTypeMatches, AuthorityRecords);
resolve_no_exact_type_match(Message, Qname, Qtype, _Host, _CnameChain, _ExactTypeMatches, Zone, MatchedRecords, ReferralRecords, AuthorityRecords) ->
  ResolvedMessage = resolve_exact_match_referral(Message, Qtype, MatchedRecords, ReferralRecords, AuthorityRecords),
  sign_records(ResolvedMessage, Qname, Qtype, Zone, [], AuthorityRecords).



% Given an exact name match where the Qtype is not found in the record set and we are not authoritative,
% add the NS records to the authority section of the message.
resolve_exact_match_referral(Message, _Qtype, _MatchedRecords, ReferralRecords, _AuthorityRecords = []) ->
  Message#dns_message{authority = Message#dns_message.authority ++ ReferralRecords};

% Given an exact name match and the type of ANY, return all of the matched records.
resolve_exact_match_referral(Message, ?DNS_TYPE_ANY, MatchedRecords, _ReferralRecords, _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = MatchedRecords};
% Given an exact name match and the type NS, where the NS records are not found in record set
% return the NS records in the answers section of the message.
resolve_exact_match_referral(Message, ?DNS_TYPE_NS, _MatchedRecords, ReferralRecords, _AuthorityRecords) ->
  Message#dns_message{aa = true, answers = ReferralRecords};
% Given an exact name match and the type SOA, where the SOA record is not found in the records set,
% return the SOA records in the answers section of the message.
resolve_exact_match_referral(Message, ?DNS_TYPE_SOA, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
  Message#dns_message{aa = true, answers = AuthorityRecords};
% Given an exact name match where the Qtype is not found in the record set and is not ANY, SOA or NS,
% return the SOA records for the zone in the authority section of the message and set the RC to
% NOERROR.
resolve_exact_match_referral(Message, _, _MatchedRecords, _ReferralRecords, AuthorityRecords) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ AuthorityRecords}.



% There is a CNAME record and the request was for a CNAME record so append the CNAME records to
% the answers section..
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, Zone, CnameRecords) ->
  case is_dnssec(Message, Zone) of
    true ->
      Message#dns_message{aa = true, answers = Message#dns_message.answers ++ erldns_dnssec:sign_records(Message, Zone, CnameRecords)};
    false ->
      Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}
  end;

% There is a CNAME record, however the Qtype is not CNAME, check for a CNAME loop before continuing.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords) ->
  resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, MatchedRecords, Zone, CnameRecords, lists:member(lists:last(CnameRecords), CnameChain)).

%% Indicates a CNAME loop. The response code is a SERVFAIL in this case.
resolve_exact_match_with_cname(Message, _Qtype, _Host, _CnameChain, _MatchedRecords, _Zone, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
% No CNAME loop, restart the query with the CNAME content.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, CnameRecords, false) ->
  CnameRecord = lists:last(CnameRecords),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  ResolvedMessage = Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords},
  case is_dnssec(Message, Zone) of
    true ->
      SignedMessage = erldns_dnssec:sign_message(ResolvedMessage, Name, Qtype, Zone, CnameRecords),
      restart_query(SignedMessage, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name));
    false ->
      restart_query(ResolvedMessage, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name))
  end.



% The CNAME is in the zone so we do not need to look it up again.
restart_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  substitute_wildcards(resolve(Message, Name, Qtype, Zone, Host, CnameChain), Name);
% The CNAME is not in the zone, so we need to find the zone using the
% CNAME content.
restart_query(Message, Name, Qtype, Host, CnameChain, _Zone, false) ->
  resolve(Message, Name, Qtype, erldns_zone_cache:find_zone(Name), Host, CnameChain).

% Delegated, but in the same zone.
restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  resolve(Message, Name, Qtype, Zone, Host, CnameChain);
% Delegated to a different zone.
restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, false) ->
  resolve(Message, Name, Qtype, erldns_zone_cache:find_zone(Name, Zone#zone.authority), Host, CnameChain). % Zone lookup



% There was no exact match for the Qname, so we use the best matches that were
% returned by the best_match() function.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), BestMatchRecords), % NS lookup
  best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).

% There were no NS records in the best matches.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, []) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone);
% There were NS records in the best matches, so this is a referral.
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords).


% There is no referral, so check to see if there is a wildcard.
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, lists:any(erldns_records:match_wildcard(), BestMatchRecords)).

%% It's a wildcard match
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, true) ->
  CnameRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), BestMatchRecords),
  resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords);
%% It is not a wildcard.
resolve_best_match(Message, Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, false) ->
  [Question|_] = Message#dns_message.questions,
  case Qname =:= Question#dns_query.name of
    true ->
      Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Message#dns_message.authority ++ Zone#zone.authority, aa = true};
    false ->
      Message
  end.


% It's a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, []) ->
  TypeMatchedRecords = case Qtype of
                         ?DNS_TYPE_ANY ->
                           filter_records(MatchedRecords, erldns_handler:get_handlers());
                         _ ->
                           lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
                       end,
  case TypeMatchedRecords of
    [] ->
      %% Ask the custom handlers for their records.
      NewRecords = lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords), erldns_handler:get_handlers())),
      resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, [], NewRecords);
    _ ->
      resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, [], TypeMatchedRecords)
  end;

% It is a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords).

% It is not a CNAME and there were no exact type matches
resolve_best_match_with_wildcard(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, _CnameRecords = [], _TypeMatches = []) ->
  Message#dns_message{aa = true, authority = Message#dns_message.authority ++ Zone#zone.authority};

% It is not a CNAME and there were exact type matches
resolve_best_match_with_wildcard(Message, Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, _CnameRecords = [], TypeMatches) ->
  Records = TypeMatches,
  NewMessage = Message#dns_message{aa = true, answers = Message#dns_message.answers ++ Records},
  SignedMessage = case is_dnssec(Message, Zone) of
    true -> erldns_dnssec:sign_wildcard_message(NewMessage, Qname, Zone, TypeMatches);
    false -> NewMessage
  end,
  SignedMessage.


% It is a CNAME and the Qtype was CNAME
resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _CnameChain, _BestMatchRecords, _Zone, CnameRecords) ->
  Records = CnameRecords,
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ Records};

% It is a CNAME and the Qtype was not CNAME
resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  % There should only be one CNAME. Multiple CNAMEs kill unicorns.
  CnameRecord = lists:last(CnameRecords),
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords, lists:member(CnameRecord, CnameChain)).

% Indicates CNAME loop
resolve_best_match_with_wildcard_cname(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, _CnameRecords, true) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};

% We should follow the CNAME
resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, _BestMatchRecords, Zone, CnameRecords, false) ->
  FollowedCnameRecord = lists:last(CnameRecords),
  FollowedCname = FollowedCnameRecord#dns_rr.name,
  CnameAnswers = CnameRecords,
  CnameRecord = lists:last(CnameAnswers),
  Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
  NewMessage = substitute_wildcards(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameAnswers}, Qname),


  % Should the records that are added to the Cname chain be synthesized here?
  case is_dnssec(Message, Zone) of
    true ->
      SignedNewMessage = erldns_dnssec:sign_wildcard_message(NewMessage, Qname, Zone, CnameRecords, FollowedCname),
      restart_query(SignedNewMessage, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name));
    false -> 
      restart_query(NewMessage, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name))
  end.



% There are referral records
resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords) ->
  resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords, lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), BestMatchRecords)). % Lookup SOA in best match records

% Indicate that we are not authoritative for the name as there were no
% SOA records in the best-match results. The name has thus been delegated
% to another authority.
%
% Note that in this case the referral records should not be signed since we
% are not authoritative.
resolve_best_match_referral(Message, _Qname, _Qtype, _Host, _CnameChain, _BestMatchRecords, _Zone, ReferralRecords, []) ->
  Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};

% We are authoritative for the name since there was an SOA record in
% the best match results.
resolve_best_match_referral(Message, Qname, Qtype, _Host, _CnameChain = [], _BestMatchRecords, Zone, _ReferralRecords, AuthorityRecords) ->
  {ok, ZoneWithRecords} = erldns_zone_cache:get_zone_with_records(Zone#zone.name),
  ResponseCode = case lists:any(erldns_records:match_any_subdomain(Qname), ZoneWithRecords#zone.records) of
                   true -> ?DNS_RCODE_NOERROR;
                   false -> ?DNS_RCODE_NXDOMAIN
                 end,

  ResolvedMessage = Message#dns_message{aa = true, rc = ResponseCode, authority = Message#dns_message.authority ++ AuthorityRecords},
  sign_records(ResolvedMessage, Qname, Qtype, Zone, [], AuthorityRecords);


% We are authoritative and the Qtype is ANY so we just return the 
% original message.
resolve_best_match_referral(Message, _Qname, ?DNS_TYPE_ANY, _Host, _CnameChain, _BestMatchRecords, _Zone, _ReferralRecords, _Authority) ->
  Message;
resolve_best_match_referral(Message, Qname, Qtype, _Host, _CnameChain, _BestMatchRecords, Zone, _ReferralRecords, AuthorityRecords) ->
  ResolvedMessage = Message#dns_message{authority = Message#dns_message.authority ++ AuthorityRecords},
  sign_records(ResolvedMessage, Qname, Qtype, Zone, [], AuthorityRecords).




% Find the best match records for the given Qname in the
% given zone. This will attempt to walk through the
% domain hierarchy in the Qname looking for both exact and
% wildcard matches.
-spec best_match(dns:dname(), #zone{}) -> [dns:rr()].
best_match(Qname, Zone) -> best_match(Qname, dns:dname_to_labels(Qname), Zone).

best_match(_Qname, _Labels = [], _Zone) -> [];
best_match(Qname, _Labels = [_|Rest], Zone) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  best_match(Qname, Rest, Zone,  erldns_zone_cache:get_records_by_name(WildcardName)).

-spec best_match(dns:dname(), [dns:label()], erldns:zone(), [dns:rr()]) -> [dns:rr()].
best_match(_Qname, _Labels = [], _Zone, []) -> [];
best_match(Qname, Labels, Zone, []) ->
  Name = dns:labels_to_dname(Labels),
  case erldns_zone_cache:get_records_by_name(Name) of
    [] -> best_match(Qname, Labels, Zone);
    Matches -> Matches
  end;
best_match(_Qname, _Labels, _Zone, WildcardMatches) -> WildcardMatches.


%% @doc Replaces any wildcard records in the answers section of
%% the message with the Qname.
substitute_wildcards(Message, Qname) ->
  Message#dns_message{
    answers = lists:map(substitute_wildcards_fun(Qname), Message#dns_message.answers)
   }.

%% @doc A higher order function for substituting wildcards with the given Qname.
%%
%% @todo Move this to erldns_records
substitute_wildcards_fun(Qname) ->
  fun(R) ->
      R#dns_rr{name = erldns_records:wildcard_substitution(R#dns_rr.name, Qname)}
  end.



%% @doc Function for executing custom lookups by registered handlers.
-spec custom_lookup(dns:dname(), dns:type(), [dns:rr()]) -> fun(({module(), [dns:type()]}) -> [dns:rr()]).
custom_lookup(Qname, Qtype, Records) ->
  fun({Module, Types}) ->
      case lists:member(Qtype, Types) of
        true -> Module:handle(Qname, Qtype, Records);
        false ->
          case Qtype =:= ?DNS_TYPE_ANY of
            true -> Module:handle(Qname, Qtype, Records);
            false -> []
          end
      end
  end.

% @doc Function for filtering out custom records and replcing them with
% records which content from the custom handler.
filter_records(Records, []) -> Records;
filter_records(Records, [{Handler,_}|Rest]) ->
  filter_records(Handler:filter(Records), Rest).


%% @doc According to RFC 2308 the TTL for the SOA record in an NXDOMAIN response
%% must be set to the value of the minimum field in the SOA content.
rewrite_soa_ttl(Message) -> Message#dns_message{authority = rewrite_soa_records_ttl(Message#dns_message.authority)}.

rewrite_soa_records_ttl([]) -> [];
rewrite_soa_records_ttl(Records) -> rewrite_soa_records_ttl(Records, []).
rewrite_soa_records_ttl([], NewRecords) -> NewRecords;
rewrite_soa_records_ttl([R|Rest], NewRecords) -> rewrite_soa_records_ttl(Rest, NewRecords ++ [erldns_records:minimum_soa_ttl(R, R#dns_rr.data)]).

%% See if additional processing is necessary.
additional_processing(Message, _Host, {error, _}) ->
  Message;
additional_processing(Message, Host, Zone) ->
  RequiresAdditionalProcessing = requires_additional_processing(Message#dns_message.answers ++ Message#dns_message.authority, []),
  additional_processing(Message, Host, Zone, lists:flatten(RequiresAdditionalProcessing)).

%% No records require additional processing.
additional_processing(Message, _Host, _Zone, []) ->
  Message;
%% There are records with names that require additional processing.
additional_processing(Message, Host, Zone, Names) ->
  RRs = lists:flatten(lists:map(fun(Name) -> erldns_zone_cache:get_records_by_name(Name) end, Names)),
  Records = lists:filter(erldns_records:match_types([?DNS_TYPE_A, ?DNS_TYPE_AAAA]), RRs),
  additional_processing(Message, Host, Zone, Names, Records).

%% No additional A records were found, so just return the message.
additional_processing(Message, _Host, _Zone, _Names, []) ->
  Message;
%% Additional A records were found, so we add them to the additional section.
additional_processing(Message, _Host, _Zone, _Names, Records) ->
  Message#dns_message{additional=Message#dns_message.additional ++ Records}.



%% Given a list of answers find the names that require additional processing.
requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
            Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
            Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
            _ -> []
          end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% @doc Return true if the zone is signed, DNSSEC is request and DNSSEC is enabled.
is_dnssec(Message, Zone) ->
  is_signed_zone(Zone) and proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) and erldns_config:use_dnssec().

%% @doc Return true if the zone_signing_key is defined in the zone.
is_signed_zone(Zone) ->
  case Zone#zone.zone_signing_key of
    undefined -> false;
    _ -> true
  end.

%% @doc Return true if DNSSEC is requested and enabled.
check_dnssec(Message, Host, Question) ->
  case proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) of
    true ->
      erldns_events:notify({dnssec_request, Host, Question#dns_query.name}),
      erldns_config:use_dnssec();
    false -> false
  end.

%% @doc Returns true if the given Qname is found at the zone apex.
is_apex(Qname, Zone) ->
  Qname =:= Zone#zone.name.

%% @doc Signs the additional answer and authority records if necessary.
-spec sign_records(dns:message(), dns:dname(), dns:type(), erldns:zone(), [dns:rr()], [dns:rr()]) -> dns:message().
sign_records(Message, Qname, Qtype, Zone, AnswerRecords, AuthorityRecords) ->
  case is_dnssec(Message, Zone) of
    true -> erldns_dnssec:sign_message(Message, Qname, Qtype, Zone, AnswerRecords, AuthorityRecords);
    false -> Message
  end.
