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
        vm.visitorsChartData = [];

        vm.chartOptions = {
            chart: {
                type: 'pieChart',
                height: 210,
                donut: true,
                x: function (d) { return d.key; },
                y: function (d) { return d.y; },
                valueFormat: (d3.format(".0f")),
                color: [ '#E75753', '#E75753'],
                showLabels: false,
                showLegend: false,
                margin: { top: -10 }
            }
        };

        server.getAlarmsCount().then(function(response) {

            vm.chartOptions.chart.title = response.data.c.toString();
            vm.visitorsChartData = [ {key: 'DFA_Unknown', y: response.data.c} ];
        });

    }
})();
