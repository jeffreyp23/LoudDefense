var express = require('express');
var router = express.Router();

var fs = require('fs');

var bropath = "/usr/local/bro/bin/broctl";
var sitepath = "/usr/local/bro/share/bro/site/local.bro";

router.post('/', function (req, res, next) {

    if (typeof req.body.value === 'undefined') {
        res.sendStatus(400);
        return;
    }

    fs.readFile(sitepath, function (err, data) {
        if (err) {
            res.status(500).json(err);
        } else {

            var theFile = data.toString().split("\n");
            theFile.splice(-1, 1);

            if (req.body.value) {
                theFile.push("redef S7Dfa::enforcement_mode = T;");
            } else {
                theFile.push("redef S7Dfa::enforcement_mode = F;");
            }

            fs.writeFile(sitepath, theFile.join("\n"), function (err) {
                if (err) {
                    res.status(500).json(err);
                } else {

                    require('child_process').exec(bropath + " deploy");

                    res.sendStatus(200);
                }

            });

        }
    });

});

module.exports = router;
