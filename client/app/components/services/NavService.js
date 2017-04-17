(function(){
  'use strict';

  angular.module('app')
          .service('navService', [
          '$q',
          navService
  ]);

  function navService($q){
    var menuItems = [
      {
        name: 'Dashboard',
        icon: 'dashboard',
        sref: '.dashboard'
      },
      {
        name: 'Alarms',
        icon: 'person',
        sref: '.alarms'
      },
      {
        name: 'Assets',
        icon: 'view_module',
        sref: '.assets'
      },
      {
        name: 'Logs',
        icon: 'view_module',
        sref: '.logs'
      }
    ];

    return {
      loadAllItems : function() {
        return $q.when(menuItems);
      }
    };
  }

})();
