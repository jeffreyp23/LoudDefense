/**
 * Created by jeffreypaul on 17/04/2017.
 */

var express = require('express');
var router = express.Router();

var fs = require('fs');

var noticeFilePath = "./Bro/weird.log";

router.get('/', function(req, res, next) {


    var lineReader = require('readline').createInterface({
        input: require('fs').createReadStream(noticeFilePath)
    });

    var logs = [];

    lineReader.on('line', function (line) {

        if(line[0] !== '#') {

            var properties = line.split(/\s{2,}/);

            logs.push({
                srcip: properties[2],
                dstip: properties[4],
                port: properties[5],
                log: properties[6]
            });
        }
    });

    lineReader.on('close', function () {
        res.json(logs);
    });

});

module.exports = router;
