(function () {
    angular
        .module('app')
        .controller('AlarmsController', [
            'server',
            '$scope',
            WarningsController
        ]);

    function WarningsController(server, $scope) {
        var vm = this;

        vm.count = 0;

        server.getAlarmsCount().then(function(response) {
            vm.count = response.data.c;
        });

    }
})();
