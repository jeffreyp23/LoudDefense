/**
 * Created by jeffreypaul on 15/06/2017.
 */

var express = require('express');
var router = express.Router();

var cplcd_status = 'Unknown';

router.post('/', function (req, res, next) {

    if(typeof req.body.status === 'undefined') {
        res.sendStatus(400);
        return;
    }

    if(req.body.status === '1') {

        cplcd_status = 'Fine';
        res.sendStatus(200);

    } else if(req.body.status === '0') {

        cplcd_status = 'Alarm';
        res.sendStatus(200);

    } else {
        res.sendStatus(400);
    }

});

router.get('/', function (req, res, next) {

    res.json({status: cplcd_status});
});


module.exports = router;