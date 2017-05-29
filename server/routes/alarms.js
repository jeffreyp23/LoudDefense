/**
 * Created by jeffreypaul on 17/04/2017.
 */

var express = require('express');
var router = express.Router();

var fs = require('fs');

var sqlite3 = require('sqlite3').verbose();

var noticeFilePath = "./Bro/bro_notice.sqlite";


router.get('/count', function (req, res, next) {

    fs.access(noticeFilePath, fs.constants.F_OK, function (err) {

        if (!err) {

            var db = new sqlite3.Database(noticeFilePath);

            var count = 0;

            db.serialize(function () {

                db.each("SELECT COUNT(*) AS c FROM notice", function (err, row) {

                    if (err) {
                        console.log(err);
                    } else {

                        count = row.c;
                    }
                });

            });

            db.close(function () {
                res.json({c: count});
            });

        } else {

            res.json({c: 0});
        }
    });

});

router.get('/', function (req, res, next) {

    fs.access(noticeFilePath, fs.constants.F_OK, function (err) {

        if (!err) {

            var db = new sqlite3.Database(noticeFilePath);

            var alarms = [];

            db.serialize(function () {

                db.each("SELECT * FROM notice ORDER BY ts DESC", function (err, row) {

                    if (err) {
                        console.log(err);
                    } else {

                        alarms.push({
                            srcip: row["id.orig_h"],
                            dstip: row["id.resp_h"],
                            state: row["msg"]
                        });

                    }
                });

            });

            db.close(function () {
                res.json(alarms);
            });

        } else {
            res.json([]);
        }
    });

});

module.exports = router;
