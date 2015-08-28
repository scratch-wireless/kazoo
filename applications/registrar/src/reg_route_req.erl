%%%-------------------------------------------------------------------
%%% @copyright (C) 2012-2014, 2600Hz INC
%%% @doc
%%% Look up IP for authorization/replaying of route_req
%%% @end
%%% @contributors
%%%   James Aimonetti
%%%-------------------------------------------------------------------
-module(reg_route_req).

-export([init/0
         ,handle_route_req/2
        ]).

-include("reg.hrl").

-spec init() -> 'ok' | 'remove'.
init() ->
    whapps_maintenance:refresh(?WH_SIP_DB).

-spec handle_route_req(wh_json:object(), wh_proplist()) -> any().
handle_route_req(JObj, _Props) ->
    'true' = wapi_route:req_v(JObj),
    wh_util:put_callid(JObj),

    CCVs = wh_json:get_value(<<"Custom-Channel-Vars">>, JObj, wh_json:new()),
    case wh_json:get_ne_value(<<"Account-ID">>, CCVs) of
        'undefined' -> maybe_replay_route_req(JObj, CCVs);
        _AccountId -> 'ok'
    end.

-spec maybe_replay_route_req(wh_json:object(), wh_json:object()) -> 'ok'.
-spec maybe_replay_route_req(wh_json:object(), wh_json:object(), api_binary()) -> 'ok'.
maybe_replay_route_req(JObj, CCVs) ->
    maybe_replay_route_req(JObj, CCVs, wh_json:get_value(<<"From-Network-Addr">>, JObj)).

maybe_replay_route_req(_JObj, _CCVs, 'undefined') ->
    lager:debug("failing to reply route req with no IP to use");
maybe_replay_route_req(JObj, CCVs, IP) ->
    case reg_authn_req:lookup_account_by_ip(IP) of
        {'ok', AccountCCVs} ->
            lager:debug("route req was missing account information, loading from IP ~s and replaying", [IP]),
            wapi_route:publish_req(
              wh_json:set_value(<<"Custom-Channel-Vars">>
                                ,wh_json:set_values(AccountCCVs, CCVs)
                                ,JObj
                               )
             );
        {'error', _E} ->
            lager:debug("failed to find account information from IP ~s", [IP]),
            FromHeader = wh_json:get_value(<<"From">>, JObj),
            [FromUser, _] = binary:split(FromHeader, <<"@">>),
            lookup_account_using_from(JObj, CCVs, FromUser, IP)
    end.

-spec lookup_account_using_from(wh_json:object(), wh_json:object(), api_binary(), api_binary()) -> 'ok'.
lookup_account_using_from(_JObj, _CCVs, 'undefined', _IP) ->
    lager:debug("failed to find account information since there was no from user to use");
lookup_account_using_from(JObj, CCVs, FromUser, IP) ->
    case reg_authn_req:lookup_account_by_from(FromUser, IP) of
        {'ok', AccountCCVs} ->
            lager:debug("authz request was missing account information, loading from FromUser ~s and IP ~s and replaying", [FromUser, IP]),
            Req = maybe_add_caller_id_to_request(JObj, AccountCCVs),
            wapi_route:publish_req(
              wh_json:set_value(<<"Custom-Channel-Vars">>
                                ,wh_json:set_values(AccountCCVs, CCVs)
                                ,Req
                               )
             );
        {'error', _E} ->
            lager:debug("failed to find account information from FromUser ~s and IP ~s, not replaying", [FromUser, IP])
    end.

-spec maybe_add_caller_id_to_request(wh_json:object(), wh_proplist()) -> wh_json:object().
maybe_add_caller_id_to_request(JObj, CCVs) ->
    AccountId = props:get_value(<<"Account-ID">>, CCVs),
    AccountDb = wh_util:format_account_id(AccountId, 'encoded'),
    DeviceId = props:get_value(<<"Authorizing-ID">>, CCVs),
    case couch_mgr:open_cache_doc(AccountDb, DeviceId) of
        {'error', _err} -> JObj;
        {'ok', DeviceDoc} ->
            Name = wh_json:get_ne_value([<<"caller_id">>, <<"external">>, <<"name">>], DeviceDoc),
            Number = wh_json:get_ne_value([<<"caller_id">>, <<"external">>, <<"number">>], DeviceDoc),
            lager:info("setting caller id to ~s <~s>", [Number, Name]),
            wh_json:set_values([{<<"Caller-ID-Name">>, Name}
                                ,{<<"Caller-ID-Number">>, Number}
                               ], JObj)
    end.
