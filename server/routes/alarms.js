/**
 * Created by jeffreypaul on 17/04/2017.
 */

var express = require('express');
var router = express.Router();

var fs = require('fs');

var noticeFilePath = "./Bro/notice.log";

router.get('/', function(req, res, next) {


    var lineReader = require('readline').createInterface({
        input: require('fs').createReadStream(noticeFilePath)
    });

    var alarms = [];

    lineReader.on('line', function (line) {

        if(line[0] !== '#') {

            var properties = line.split(/\s{2,}/);

            alarms.push({
                srcip: properties[2],
                dstip: properties[4],
                state: properties[10]
            });
        }
    });

    lineReader.on('close', function () {
        res.json(alarms);
    });

});

module.exports = router;
