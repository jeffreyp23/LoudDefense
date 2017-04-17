(function () {

    angular
        .module('app')
        .controller('AssetsController', [
            'server',
            '$scope',
            AssetsController
        ]);

    function AssetsController(server, $scope) {
        var vm = this;

        vm.tableData = [];
        $scope.selected = [];

        server.getAssets().then(function (response) {

            angular.copy(response.data, vm.tableData);
            vm.totalItems = response.data.length;

        });
    }

})();
