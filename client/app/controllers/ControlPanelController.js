(function () {

    angular
        .module('app')
        .controller('ControlPanelController', [
            '$mdDialog', '$interval', 'server',
            ControlPanelController
        ]);

    function ControlPanelController($mdDialog, $interval, server) {
        var vm = this;

        vm.buttonEnabled = false;
        vm.showProgress = false;
        vm.reloadServer = 'learningMode';
        vm.performProgress = performProgress;
        vm.determinateValue = 10;

        function performProgress() {

            vm.showProgress = true;
            var sendData = {};

            if (vm.reloadServer === 'learningMode') {
                sendData.value = false;
            } else {
                sendData.value = true;
            }

            server.postMode(sendData.value).then(function () {
                vm.showProgress = false;
                showAlert();
            });
        }

        function showAlert() {
            alert = $mdDialog.alert({
                title: 'Reloading done',
                content: "Switched to " + (vm.reloadServer === 'learningMode' ? 'learning mode' : 'enforcement mode'),
                ok: 'Close'
            });
            $mdDialog
                .show(alert)
                .finally(function () {
                    alert = undefined;
                });
        }
    }

})();
