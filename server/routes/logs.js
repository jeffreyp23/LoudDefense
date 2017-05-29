/**
 * Created by jeffreypaul on 17/04/2017.
 */

var express = require('express');
var router = express.Router();

var fs = require('fs');

var sqlite3 = require('sqlite3').verbose();

var logsFilePath = "./Bro/bro_weird.sqlite";


router.get('/', function (req, res, next) {

    fs.access(logsFilePath, fs.constants.F_OK, function (err) {

        if (!err) {

            var db = new sqlite3.Database(logsFilePath);

            var logs = [];

            db.serialize(function () {

                db.each("SELECT * FROM weird ORDER BY ts DESC", function (err, row) {

                    if (err) {
                        console.log(err);
                    } else {

                        logs.push({
                            srcip: row["id.orig_h"],
                            dstip: row["id.resp_h"],
                            port: row["id.resp_p"],
                            log: row["name"]
                        });

                    }
                });

            });

            db.close(function () {
                res.json(logs);
            });

        } else {

            res.json([]);
        }
    });

});

module.exports = router;
