(function(){

  angular
    .module('app')
    .controller('LogsController', [
      'server',
      '$scope',
      TableController
      
    ]);

  function TableController(server , $scope) {
    var vm = this;

    vm.tableData = [];
    $scope.selected = [];

    server.getLogs().then(function (response) {

      angular.copy(response.data, vm.tableData);
      vm.totalItems = response.data.length;

    });

  }

})();
