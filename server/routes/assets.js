/**
 * Created by jeffreypaul on 17/04/2017.
 */

var express = require('express');
var router = express.Router();

var fs = require('fs');

var sqlite3 = require('sqlite3').verbose();

var assetsFilePath = "/var/log/bro_assets.sqlite";

router.get('/', function (req, res, next) {

    fs.access(assetsFilePath, fs.constants.F_OK, function (err) {

        if (!err) {

            var db = new sqlite3.Database(assetsFilePath);

            var assets = [];

            db.serialize(function () {

                db.each("SELECT * FROM assets", function (err, row) {

                    if (err) {
                        console.log(err);
                    } else {

                        assets.push({
                            ip: row["ip"],
                            name: ""
                        });

                    }
                });

            });

            db.close(function () {
                res.json(assets);
            });

        } else {
            res.json([]);
        }

    });

});

module.exports = router;
