(function () {

    angular
        .module('app')
        .controller('AlarmsGridController', [
            'server',
            '$scope',
            AlarmsGridController
        ]);

    function AlarmsGridController(server, $scope) {
        var vm = this;

        vm.tableData = [];
        $scope.selected = [];

        server.getAlarms().then(function (response) {

            angular.copy(response.data, vm.tableData);
            vm.totalItems = response.data.length;

        });
    }

})();
