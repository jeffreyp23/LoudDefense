/**
 * Created by jeffreypaul on 15/06/2017.
 */

(function () {
    angular
        .module('app')
        .controller('CPLCDController', [
            'server',
            CPLCDController
        ]);

    function CPLCDController(server) {
        var vm = this;

        vm.status = '';

        server.getCPLCD().then(function(response) {

            vm.status = response.data.status;

            if(vm.status === 'Fine') {
                vm.status_color = 'green';
            } else if(vm.status === 'Alarm') {
                vm.status_color = 'red';
            } else {
                vm.status_color = 'orange';
            }
        });
    }
})();
