/**
 * Created by jeffreypaul on 17/04/2017.
 */

(function(){
    'use strict';

    angular.module('app')
        .service('server', [
            '$http',
            server
        ]);

    function server($http){

        var url = "http://localhost:9000/api";


        return {
            getAlarms : function() {
                return $http.get(url + '/alarms')
            },
            getAssets: function() {
                return $http.get(url + '/assets')
            },
            getLogs: function() {
                return $http.get(url + '/logs')
            }
        };
    }

})();
