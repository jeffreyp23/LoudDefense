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
        sref: '.profile'
      },
      {
        name: 'Assets',
        icon: 'view_module',
        sref: '.table'
      },
      {
        name: 'Logs',
        icon: 'view_module',
        sref: '.data-table'
      }
    ];

    return {
      loadAllItems : function() {
        return $q.when(menuItems);
      }
    };
  }

})();
