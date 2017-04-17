/**
 * Created by jeffreypaul on 17/04/2017.
 */

var express = require('express');
var router = express.Router();

var fs = require('fs');

var noticeFilePath = "./Bro/dfa.log";

router.get('/', function (req, res, next) {


    var lineReader = require('readline').createInterface({
        input: require('fs').createReadStream(noticeFilePath)
    });

    var assets = [];

    lineReader.on('line', function (line) {

        if (line[0] !== '#') {

            var properties = line.split(/\s{2,}/);

            if (assets.filter(function (item) {
                    return item.ip === properties[0]
                }).length === 0) {

                assets.push({
                    ip: properties[0],
                    name: properties[1].split(/\s/)[0] + " device",
                });

            }
        }
    });

    lineReader.on('close', function () {
        res.json(assets);
    });

});

module.exports = router;
