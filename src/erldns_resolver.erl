%% Copyright (c) 2012-2018, DNSimple Corporation
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

-include_lib("dns_erlang/include/dns.hrl").
-include("erldns.hrl").

-export([resolve/3]).


%% @doc Resolve the first question in the message. If no message is present, return the original
%% message. If multiple questions are present, only resolve the first question.
-spec(resolve(
        Message :: dns:message(),
        AuthorityRecords :: [dns:rr()],
        Host :: dns:ip()) ->
  dns:message()).
resolve(Message, AuthorityRecords, Host) ->
  case Message#dns_message.questions of
    [] -> Message;
    [Question] -> resolve_question(Message, AuthorityRecords, Host, Question);
    [Question|_] -> resolve_question(Message, AuthorityRecords, Host, Question)
  end.


%% @doc Start the resolution process on the given question.
%% Step 1: Set the RA bit to false as we do not handle recursive queries.
%%
%% Refuse all RRSIG requests.
-spec(resolve_question(
        Message :: dns:message(),
        AuthorityRecords :: [dns:rr()],
        Host :: dns:ip(),
        Questions :: dns:questions() | dns:query()) ->
  dns:message()).
resolve_question(Message, AuthorityRecords, Host, Question) when is_record(Question, dns_query) ->
  case Question#dns_query.type of
    ?DNS_TYPE_RRSIG ->
      Message#dns_message{ra = false, ad = false, cd = false, rc = ?DNS_RCODE_REFUSED};
    Qtype ->
      check_dnssec(Message, Host, Question),
      resolve_qname_and_qtype(Message#dns_message{ra = false, ad = false, cd = false}, AuthorityRecords, Question#dns_query.name, Qtype, Host)
  end.

%% @doc With the extracted Qname and Qtype in hand, find the nearest zone
%% Step 2: Search the available zones for the zone which is the nearest ancestor to QNAME
%%
%% If the request required DNSSEC, apply the DNSSEC records. Sort answers prior to returning.
-spec resolve_qname_and_qtype(dns:message(), [dns:rr()], dns:dname(), dns:type(), dns:ip()) -> dns:message().
resolve_qname_and_qtype(Message, AuthorityRecords, Qname, Qtype, Host) ->
  case erldns_zone_cache:find_zone(Qname, lists:last(AuthorityRecords)) of
    {error, not_authoritative} ->
      %% No SOA was found for the Qname so we return the root hints
      %% Note: it seems odd that we are indicating we are authoritative here.
      case erldns_config:use_root_hints() of
        true ->
          {Authority, Additional} = erldns_records:root_hints(),
          Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = Authority, additional = Message#dns_message.additional ++ Additional};
        _ ->
          Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR}
      end;
    Zone ->
      Records = resolve_authoritative(Message, Qname, Qtype, Zone, Host, _CnameChain = []),
      sort_answers(erldns_dnssec:handle(additional_processing(erldns_records:rewrite_soa_ttl(Records), Host, Zone), Zone, Qname, Qtype))
  end.


%% An SOA was found, thus we are authoritative and have the zone.
%% Step 3: Match records
resolve_authoritative(Message, Qname, Qtype, Zone, Host, CnameChain) ->
  Result = case {erldns_zone_cache:record_name_in_zone(Zone#zone.name, Qname), CnameChain} of
             {false, []} ->
               lager:debug("Record name is not in zone (zone: ~p, qname: ~p)", [Zone#zone.name, Qname]),
               Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Zone#zone.authority};
             _ ->
               resolve(Message, Qname, Qtype, erldns_zone_cache:get_records_by_name(Qname), Host, CnameChain, Zone)
           end,

  case detect_zonecut(Zone, Qname) of
    [] ->
      Result;
    Records ->
      CnameAnswers = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), Result#dns_message.answers),
      FilteredCnameAnswers = lists:filter(fun(RR) ->
                                              case detect_zonecut(Zone, RR#dns_rr.data#dns_rrdata_cname.dname) of
                                                [] -> false;
                                                _ -> true
                                              end
                                          end, CnameAnswers),
      Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Records, answers = FilteredCnameAnswers}
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
  AuthorityRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), MatchedRecords), % Query matched records for SOA type
  TypeMatches = case Qtype of
                  ?DNS_TYPE_ANY ->
                    filter_records(MatchedRecords, erldns_handler:get_versioned_handlers());
                  _ ->
                    lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
                end,
  case TypeMatches of
    [] ->
      %% Ask the custom handlers for their records.
      Handlers = erldns_handler:get_versioned_handlers(),
      CustomHandlerRecords = lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords, Message), Handlers)),
      NewRecords = erldns_dnssec:maybe_sign_rrset(Message, CustomHandlerRecords, Zone),
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, NewRecords, AuthorityRecords);
    _ ->
      resolve_exact_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, TypeMatches, AuthorityRecords)
  end.

%% There were no matches for exact name and type, so now we are looking for NS records
%% in the exact name matches.
-spec(resolve_exact_match(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        MatchedRecords :: [dns:rr()],
        Zone :: #zone{},
        ExactTypeMatches :: dns:answers(),
        AuthorityRecords :: dns:authority()) ->
  dns:message()).
resolve_exact_match(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _ExactTypeMatches = [], AuthorityRecords) ->
  ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), MatchedRecords), % Query matched records for NS type
  resolve_no_exact_type_match(Message, Qtype, Host, CnameChain, [], Zone, MatchedRecords, ReferralRecords, AuthorityRecords);
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
resolve_exact_type_match(Message, _Qname, ?DNS_TYPE_NS, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
%% There was an exact type match for something other than an NS record and we are authoritative because there is an SOA record.
resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords) ->
  % NOTE: this is a potential bug because it assumes the last record is the one to examine.
  Answer = lists:last(MatchedRecords),
  case erldns_zone_cache:get_delegations(Answer#dns_rr.name) of
    NSRecords = [] ->
      resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords);
    NSRecords ->
      NSRecord = lists:last(NSRecords),
      case erldns_zone_cache:get_authority(Qname) of
        {ok, [SoaRecord]} ->
          case SoaRecord#dns_rr.name =:= NSRecord#dns_rr.name of
            true ->
              Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords};
            false ->
              resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords)
          end;
        {error, authority_not_found} ->
          resolve_exact_type_match(Message, Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords)
      end
  end.

%% We are authoritative and there were no NS records here.
-spec(resolve_exact_type_match(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        MatchedRecords :: [dns:rr()],
        Zone :: #zone{},
        AuthorityRecords :: dns:authority(),
        NSRecords:: [dns:rr()]) ->
  dns:message()).
resolve_exact_type_match(Message, _Qname, _Qtype, _Host, _CnameChain, MatchedRecords, _Zone, _AuthorityRecords, _NSRecords = []) ->
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords, additional = Message#dns_message.additional};
%% We are authoritative and there are NS records here.
resolve_exact_type_match(Message, _Qname, Qtype, Host, CnameChain, MatchedRecords, Zone, _AuthorityRecords, NSRecords) ->
  % NOTE: there are potential bugs here because it assumes the last record is the one to examine
  Answer = lists:last(MatchedRecords),
  NSRecord = lists:last(NSRecords),
  Name = NSRecord#dns_rr.name,
  case Name =:= Answer#dns_rr.name of
    true -> % Handle NS recursion breakout
      Message#dns_message{aa = false, rc = ?DNS_RCODE_NOERROR, authority = Message#dns_message.authority ++ NSRecords};
    false ->
      % TODO: only restart delegation if the NS record is on a parent node
      % if it is a sibling then we should not restart
      case check_if_parent(Name, Answer#dns_rr.name) of
        true ->
          restart_delegated_query(Message, Name, Qtype, Host, CnameChain, Zone, erldns_zone_cache:in_zone(Name));
        false ->
          Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, answers = Message#dns_message.answers ++ MatchedRecords, additional = Message#dns_message.additional}
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
-spec(resolve_no_exact_type_match(
        Message :: dns:message(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        ExactTypeMatches :: dns:answers(),
        Zone :: #zone{},
        MatchedRecords :: [dns:rr()],
        ReferralRecords :: [dns:rr()],
        AuthorityRecords :: dns:authority()) ->
  dns:message()).
resolve_no_exact_type_match(Message, _Qtype, _Host, _CnameChain, [], Zone, _MatchedRecords, [], _AuthorityRecords) ->
  Message#dns_message{aa = true, authority = Zone#zone.authority};
resolve_no_exact_type_match(Message, Qtype, _Host, _CnameChain, _ExactTypeMatches, _Zone, MatchedRecords, ReferralRecords, AuthorityRecords) ->
  resolve_exact_match_referral(Message, Qtype, MatchedRecords, ReferralRecords, AuthorityRecords).



% Given an exact name match where the Qtype is not found in the record set and we are not authoritative,
% add the NS records to the authority section of the message.
-spec(resolve_exact_match_referral(
        Message :: dns:message(),
        Qtype :: 0..255,
        MatchedRecords :: [dns:rr()],
        ReferralRecords :: [dns:rr()],
        AuthorityRecords :: [dns:rr()]) ->
  dns:message()).
resolve_exact_match_referral(Message, _Qtype, _MatchedRecords, ReferralRecords, []) ->
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
  Message#dns_message{aa = true, rc = ?DNS_RCODE_NOERROR, authority = AuthorityRecords}.



% There is a CNAME record and the request was for a CNAME record so append the CNAME records to
% the answers section.
-spec(resolve_exact_match_with_cname(
        Message :: dns:message(),
        Qtype :: ?DNS_TYPE_CNAME,
        Host :: any(),
        CnameChain :: any(),
        MatchedRecords :: [dns:rr()],
        Zone :: #zone{},
        CnameRecords :: [dns:rr()]) ->
  dns:message()).
resolve_exact_match_with_cname(Message, ?DNS_TYPE_CNAME, _Host, _CnameChain, _MatchedRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
% There is a CNAME record, however the Qtype is not CNAME, check for a CNAME loop before continuing.
resolve_exact_match_with_cname(Message, Qtype, Host, CnameChain, _MatchedRecords, Zone, CnameRecords) ->
  case lists:member(lists:last(CnameRecords), CnameChain) of
    true ->
      %% Indicates a CNAME loop. The response code is a SERVFAIL in this case.
      Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
    % No CNAME loop, restart the query with the CNAME content.
    false ->
      CnameRecord = lists:last(CnameRecords),
      Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
      restart_query(Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords}, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name))
  end.



% The CNAME is in a zone. If it is the same zone, then continue the chain, otherwise return the message
-spec(restart_query(
        Message :: dns:message(),
        Name :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        Zone :: #zone{},
        InZone :: boolean()) ->
  dns:message()).
restart_query(Message, Name, Qtype, Host, CnameChain, Zone, true) ->
  Parent = check_if_parent(Zone#zone.name, Name),
  case Parent of
    true ->
      resolve_authoritative(Message, Name, Qtype, Zone, Host, CnameChain);
    false ->
      Message
  end;
% The CNAME is not in a zone, do not restart the query, return the answer.
restart_query(Message, _Name, _Qtype, _Host, _CnameChain, _Zone, false) ->
  Message.


-spec(restart_delegated_query(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        Zone :: #zone{},
        InZone :: boolean()) ->
  dns:message()).
% Delegated, but in the same zone.
restart_delegated_query(Message, Qname, Qtype, Host, CnameChain, Zone, true) ->
  resolve_authoritative(Message, Qname, Qtype, Zone, Host, CnameChain);
% Delegated to a different zone.
restart_delegated_query(Message, Qname, Qtype, Host, CnameChain, Zone, false) ->
  resolve_authoritative(Message, Qname, Qtype, erldns_zone_cache:find_zone(Qname, Zone#zone.authority), Host, CnameChain).


% There was no exact match for the Qname, so we use the best matches that were returned by the best_match() function.
-spec(best_match_resolution(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        BestMatchRecords :: [dns:rr()],
        Zone :: #zone{}) ->
  dns:message()).
best_match_resolution(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  ReferralRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_NS), BestMatchRecords), % NS lookup
  case ReferralRecords of
    [] ->
      % There were no NS records in the best matches.
      resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone);
    _ ->
      % There were NS records in the best matches, so this is a referral.
      resolve_best_match_referral(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, ReferralRecords)
  end.


% There is no referral, so check to see if there is a wildcard.
%
% If there is a wildcard present, then the resolver needs to continue to handle various possible types.
%
% If there is no wildcard present and the qname matches the original question then return NXDOMAIN.
%
% If there is no wildcard present and the qname does not match the origina question then return NOERROR
% and include root hints in the additional section if necessary.
-spec(resolve_best_match(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: 0..255,
        Host :: any(),
        CnameChain :: any(),
        BestMatchRecords :: [dns:rr()],
        Zone :: #zone{}) ->
  dns:message()).
resolve_best_match(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone) ->
  case lists:any(erldns_records:match_wildcard(), BestMatchRecords) of
    true ->
      % It's a wildcard match
      CnameRecords = lists:filter(erldns_records:match_type(?DNS_TYPE_CNAME), lists:map(erldns_records:replace_name(Qname), BestMatchRecords)),
      resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords);
    false ->
      % It's not a wildcard
      [Question|_] = Message#dns_message.questions,
      case Qname =:= Question#dns_query.name of % TODO this logic can be moved up higher in processing potentially.
        true ->
          Message#dns_message{rc = ?DNS_RCODE_NXDOMAIN, authority = Zone#zone.authority, aa = true};
        false ->
          % This happens when we have a CNAME to an out-of-balliwick hostname and the query is for
          % something other than CNAME. Note that the response is still NOERROR here.
          %
          % In the dnstest suite, this is hit by cname_to_unauth_any (and others)
          case erldns_config:use_root_hints() of
            true ->
              {Authority, Additional} = erldns_records:root_hints(),
              Message#dns_message{authority = Authority, additional = Message#dns_message.additional ++ Additional};
            _ ->
              Message
          end
      end
  end.


% Handle best match resolving with a wildcard name in the zone.
-spec(resolve_best_match_with_wildcard(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: dns:type(),
        Host :: any(),
        CnameChain :: [dns:rr()],
        BestMatchRecords :: [dns:rr()],
        Zone :: #zone{},
        CnameRecords :: [dns:rr()]) ->
  dns:message()).
resolve_best_match_with_wildcard(Message, Qname, Qtype, _Host, _CnameChain, MatchedRecords, Zone, []) ->
  TypeMatchedRecords = case Qtype of
                         ?DNS_TYPE_ANY ->
                           filter_records(MatchedRecords, erldns_handler:get_versioned_handlers());
                         _ ->
                           lists:filter(erldns_records:match_type(Qtype), MatchedRecords)
                       end,
  TypeMatches = lists:map(erldns_records:replace_name(Qname), TypeMatchedRecords),
  case TypeMatches of
    [] ->
      % There is no exact type matches for the original qtype
      % Ask the custom handlers for their records.
      CustomHandlers = erldns_handler:get_versioned_handlers(),
      CustomHandlerRecords = lists:flatten(lists:map(custom_lookup(Qname, Qtype, MatchedRecords, Message), CustomHandlers)),
      Records = lists:map(erldns_records:replace_name(Qname), CustomHandlerRecords),
      NewRecords = erldns_dnssec:maybe_sign_rrset(Message, Records, Zone),
      case NewRecords of
        [] ->
          % Custom handlers returned no answers, so set the authority section of the response and return NOERROR
          Message#dns_message{aa = true, authority=Zone#zone.authority};
        NewRecords ->
          % Custom handlers returned answers
          Message#dns_message{aa = true, answers = Message#dns_message.answers ++ NewRecords}
      end;
    _ ->
      % There is an exact type match
      Message#dns_message{aa = true, answers = Message#dns_message.answers ++ TypeMatches}
  end;
% It is a wildcard CNAME
resolve_best_match_with_wildcard(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords) ->
  resolve_best_match_with_wildcard_cname(Message, Qname, Qtype, Host, CnameChain, BestMatchRecords, Zone, CnameRecords).


% Handle the case where the wildcard is a CNAME in the zone. If the Qtype was CNAME then answer, otherwise determine if
% the CNAME should be followed
-spec(resolve_best_match_with_wildcard_cname(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: dns:type(),
        Host :: any(),
        CnameChain :: [dns:rr()],
        BestMatchRecords :: [dns:rr()],
        Zone :: #zone{},
        CnameRecords :: [dns:rr()]) ->
  dns:message()).
resolve_best_match_with_wildcard_cname(Message, _Qname, ?DNS_TYPE_CNAME, _Host, _CnameChain, _BestMatchRecords, _Zone, CnameRecords) ->
  Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords};
resolve_best_match_with_wildcard_cname(Message, _Qname, Qtype, Host, CnameChain, _BestMatchRecords, Zone, CnameRecords) ->
  CnameRecord = lists:last(CnameRecords), % There should only be one CNAME. Multiple CNAMEs kill unicorns.
  case lists:member(CnameRecord, CnameChain) of
    true ->
      % Indicates CNAME loop
      Message#dns_message{aa = true, rc = ?DNS_RCODE_SERVFAIL};
    false ->
      % Follow the CNAME
      CnameRecord = lists:last(CnameRecords),
      Name = CnameRecord#dns_rr.data#dns_rrdata_cname.dname,
      UpdatedMessage = Message#dns_message{aa = true, answers = Message#dns_message.answers ++ CnameRecords},
      restart_query(UpdatedMessage, Name, Qtype, Host, CnameChain ++ CnameRecords, Zone, erldns_zone_cache:in_zone(Name))
  end.


% There are referral records
-spec(resolve_best_match_referral(
        Message :: dns:message(),
        Qname :: dns:dname(),
        Qtype :: dns:type(),
        Host :: any(),
        CnameChain :: [dns:rr()],
        BestMatchRecords :: [dns:rr()],
        Zone :: #zone{},
        CnameRecords :: [dns:rr()]) ->
  dns:message()).
resolve_best_match_referral(Message, _Qname, Qtype, _Host, CnameChain, BestMatchRecords, _Zone, ReferralRecords) ->
  Authority = lists:filter(erldns_records:match_type(?DNS_TYPE_SOA), BestMatchRecords),
  case {Qtype, Authority, CnameChain} of
    {_,[],[]} ->
      % We are authoritative for the name since there was an SOA record in the best match results.
      Message#dns_message{aa = true, rc = ?DNS_RCODE_NXDOMAIN, authority = Authority};
    {_,_,[]} ->
      % Indicate that we are not authoritative for the name as there were novSOA records in the best-match results.
      % The name has thus been delegated to another authority.
      Message#dns_message{aa = false, authority = Message#dns_message.authority ++ ReferralRecords};
    {?DNS_TYPE_ANY,_,_} ->
      % We are authoritative and the Qtype is ANY so we just return the original message
      Message;
    _ ->
      % We are authoritative and the Qtype is something other than ANY, set the authority in the response
      Message#dns_message{authority = Authority}
  end.


%% Utility functions


% Find the best match records for the given Qname in the
% given zone. This will attempt to walk through the
% domain hierarchy in the Qname looking for both exact and
% wildcard matches.
-spec best_match(dns:dname(), #zone{}) -> [dns:rr()].
best_match(Qname, Zone) -> best_match(Qname, dns:dname_to_labels(Qname), Zone).

best_match(_Qname, [], _Zone) -> [];
best_match(Qname, [_|Rest], Zone) ->
  WildcardName = dns:labels_to_dname([<<"*">>] ++ Rest),
  best_match(Qname, Rest, Zone, erldns_zone_cache:get_records_by_name(WildcardName)).

best_match(_Qname, [], _Zone, []) -> [];
best_match(Qname, Labels, Zone, []) ->
  Name = dns:labels_to_dname(Labels),
  case erldns_zone_cache:get_records_by_name(Name) of
    [] -> best_match(Qname, Labels, Zone);
    Matches -> Matches
  end;
best_match(_Qname, _Labels, _Zone, WildcardMatches) -> WildcardMatches.

%% Function for executing custom lookups by registered handlers.
-spec custom_lookup(dns:dname(), dns:type(), [dns:rr()], dns:message()) -> fun(({module(), [dns:type()], integer()}) -> [dns:rr()]).
custom_lookup(Qname, Qtype, Records, Message) -> 
  fun({Module, Types, Version}) ->
      case Version of
        1 ->
          case lists:member(Qtype, Types) of
            true -> Module:handle(Qname, Qtype, Records);
            false ->
              case Qtype =:= ?DNS_TYPE_ANY of
                true -> Module:handle(Qname, Qtype, Records);
                false -> []
              end
          end;
        2 ->
          case lists:member(Qtype, Types) of
            true -> Module:handle(Qname, Qtype, Records, Message);
            false ->
              case Qtype =:= ?DNS_TYPE_ANY of
                true -> Module:handle(Qname, Qtype, Records, Message);
                false -> []
              end
          end
      end
  end.

% Function for filtering out custom records and replacing them with
% records which content from the custom handler.
filter_records(Records, []) -> Records;
filter_records(Records, [{Handler, _Types, Version}|Rest]) ->
  case Version of
    1 -> filter_records(Handler:filter(Records), Rest);
    2 -> filter_records(Handler:filter(Records), Rest);
    _ -> []
  end.

%% See if additional processing is necessary.
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
  Message#dns_message{additional = Message#dns_message.additional ++ Records}.



%% Given a list of answers find the names that require additional processing.
requires_additional_processing([], RequiresAdditional) -> RequiresAdditional;
requires_additional_processing([Answer|Rest], RequiresAdditional) ->
  Names = case Answer#dns_rr.data of
            Data when is_record(Data, dns_rrdata_ns) -> [Data#dns_rrdata_ns.dname];
            Data when is_record(Data, dns_rrdata_mx) -> [Data#dns_rrdata_mx.exchange];
            _ -> []
          end,
  requires_additional_processing(Rest, RequiresAdditional ++ Names).

%% @doc Return true if DNSSEC is requested and enabled.
check_dnssec(Message, Host, Question) ->
  case proplists:get_bool(dnssec, erldns_edns:get_opts(Message)) of
    true ->
      erldns_events:notify({?MODULE, dnssec_request, Host, Question#dns_query.name});
    false ->
      ok
  end.

%% @doc Sort the answers in the given message.
-spec sort_answers(dns:message()) -> dns:message().
sort_answers(Message) ->
  Message#dns_message{answers = lists:usort(fun sort_fun/2, Message#dns_message.answers)}.

-spec sort_fun(dns:rr(), dns:rr()) -> boolean().
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname=Name}},
         #dns_rr{type = ?DNS_TYPE_CNAME, name = Name}) ->
  true;
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME, name = Name},
         #dns_rr{type = ?DNS_TYPE_CNAME, data = #dns_rrdata_cname{dname=Name}}) ->
  false;
sort_fun(#dns_rr{type = ?DNS_TYPE_CNAME}, #dns_rr{}) ->
  true;
sort_fun(#dns_rr{}, #dns_rr{type = ?DNS_TYPE_CNAME}) ->
  false;
sort_fun(A, B) ->
  A =< B.

% Extract the name from the first record in the list.
zone_authority_name([Record | _]) ->
  Record#dns_rr.name.

% Find NS records that represent a zone cut.
detect_zonecut(Zone, Qname) when is_binary(Qname) ->
  detect_zonecut(Zone, dns:dname_to_labels(Qname));
detect_zonecut(_Zone, []) ->
  [];
detect_zonecut(_Zone, [_Label]) ->
  [];
detect_zonecut(Zone, [_ | ParentLabels] = Labels) ->
  Qname = dns:labels_to_dname(Labels),
  case dns:compare_dname(zone_authority_name(Zone#zone.authority), Qname) of
    true ->
      [];
    false ->
      case erldns_zone_cache:get_records_by_name_and_type(Qname, ?DNS_TYPE_NS) of
        [] ->
          detect_zonecut(Zone, ParentLabels);
        ZonecutNSRecords ->
          ZonecutNSRecords
      end
  end.
