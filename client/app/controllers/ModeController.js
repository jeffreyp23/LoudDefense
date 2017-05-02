(function () {
    angular
        .module('app')
        .controller('ModeController', [
            'server',
            MemoryController
        ]);

    function MemoryController(server) {
        var vm = this;

        vm.mode = '';

        server.getMode().then(function(response) {

            if(response.data.mode) {
                vm.mode = 'Enforcement';
            } else {
                vm.mode = 'Learning';
            }

        });
    }
})();
