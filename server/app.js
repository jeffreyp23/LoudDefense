var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var index = require('./routes/index');
var users = require('./routes/users');
var alarms = require('./routes/alarms');
var assets = require('./routes/assets');
var logs = require('./routes/logs');
var mode = require('./routes/mode');
var cplcd = require('./routes/cplcd');

var cors = require('cors');
var app = express();

app.use(cors());

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use('/', index);
app.use('/api/alarms', alarms);
app.use('/api/assets', assets);
app.use('/api/logs', logs);
app.use('/api/mode', mode);
app.use('/api/cplcd', cplcd);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  console.log(err.message);

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
