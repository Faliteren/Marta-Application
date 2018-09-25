var bodyParser = require('body-parser')
var express = require('express')
var app = express()
var port = process.env.PORT || 3000;
var path = require('path');
var server = require('http').createServer(app);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
var config = require('./config.js');
const session = require('express-session')
var uniqid = require("uniqid");
const pug = require('pug');
const mysql = require('mysql2');
var validator = require('validator');
var randomstring = require('randomstring');
var moment = require('moment');

var async = require('async');
// const connection = mysql.createConnection({
//   host: 'us-cdbr-iron-east-05.cleardb.net',
//   user: 'b2b15addfae07f',
//   password: '65be45f3',
//   database: 'heroku_fcbaefe03d0e65f'
// });

var pool  = mysql.createPool({
  host: 'us-cdbr-iron-east-05.cleardb.net',
  user: 'b2b15addfae07f',
  password: '65be45f3',
  database: 'heroku_fcbaefe03d0e65f'
});

var getConnection = function(callback) {
  pool.getConnection(function(err, connection) {
      callback(err, connection);
  });
};

connection = {}
connection["execute"] = function() {
  var arg = arguments;
  getConnection(function(err, connect) {

    var argumentList = []
    for (var i = 0; i < arg.length - 1; i++) {
      argumentList.push(arg[i]);
    }
    argumentList.push(function(err, results, fields) {
      arg[arg.length - 1](err, results, fields);
      connect.release();
    })
    // console.log(connect.execute);
    connect.execute.apply(connect, argumentList)   
  })
}

app.use(express.static('resources'))

//Session ----
app.use(session({
    secret: 'secret key xd',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
  }))

app.use( bodyParser.json() );
app.use(bodyParser.urlencoded({
  extended: true
}));


var fs = require('fs');
var needle = require('needle');

const bcrypt = require('bcrypt')
const saltRounds = 10;

app.post('/login', function (req, res) {
  var user = req.body.username;
  var pass = req.body.password;
  checkCred(user, pass, function(result) {
    if (result.valid) {
      
      req.session["user"] = user;
      req.session["IsAdmin"] = result.IsAdmin;
      res.send({"status":"SUCCESS"});
    } else {
      res.send({"status":"FAILURE", reason : result.reason  });
    }
  });

});

app.get('/session', function (req, res) {
    if (typeof req.session.user === 'undefined') {
      res.redirect("/");
    }
    else if (req.session.IsAdmin == 1) {
      res.redirect("/session/admin");
    }
    else {
      res.redirect("/session/passenger");
    }
});

app.get('/session/passenger', function (req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 1) {
    res.redirect("/session/admin");
  }
  else {
    res.sendFile(path.join(__dirname, "html/passenger.html"));    
  }
});

app.get('/session/admin', function (req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 0) {
    res.redirect("/session/passenger");
  }
  else {
    res.sendFile(path.join(__dirname, "html/admin.html"));    
  }
});

app.post("/api/breezecard/filter",  function (req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE"});
    return;
  }

  // if user, display only user's
  // if admin, display all
  var bn = req.body.BreezecardNum ? req.body.BreezecardNum : "%";
  var lower = req.body.Lower ? req.body.Lower  : "%";
  var upper = req.body.Upper ? req.body.Upper  : "%";
  var owner = req.body.Owner ? req.body.Owner  : "%";
  var suspended = req.body.Suspended == 'true' ? true : false;

  // filterBreezecards(user, numBreeze, lower, upper, callback)
  if (req.session.IsAdmin) {
    filterBreezecards(owner, bn, lower, upper, suspended,  function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status": "SUCCESS"});
    })
  } else {
    res.send({"status" : "FAILURE", "reason" : "MUST BE ADMIN"});
    
  }
});


app.get("/api/breezecard",  function (req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE"});
    return;
  }
  // if user, display only user's
  // if admin, display all
  if (req.session.IsAdmin) {
    getBreezecards(function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status": "SUCCESS"});
    })
  } else {
    getUserBreezecards(req.session.user, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status": "SUCCESS"});
    })
  }
});


app.post("/api/breezecard/add", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }
  if (req.session.IsAdmin) {
    res.send({"valid": false, reason: "Cannot be admin"});
    return;
  }
  var bn = req.body.BreezecardNum;
  // addBreezecard(numBreeze, user, callback)
  addBreezecard(bn, req.session.user, function(result) {
    res.send(result);
  });
});

app.post("/api/breezecard/remove", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }
  if (req.session.IsAdmin) {
    res.send({"valid": false, reason: "Cannot be admin"});
    return;
  }

  var bn = req.body.BreezecardNum;
  removeCardFromUser(bn, function(data) {
    checkUserBreezecards(req.session.user, function(results){});
    res.send(data);
  });

});
// updateCardValue(numBreeze, value, callback)
app.post("/api/breezecard/add_funds", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }
  if (req.session.IsAdmin) {
    res.send({"valid": false, reason: "Cannot be admin"});
    return;
  }

  var bn = req.body.BreezecardNum;
  var val = req.body.Value;

  updateCardValue(bn, val, function(data) {
    res.send(data);
  });

});


app.get("/api/allstations", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  //can only see stations if admin 
  if (req.session.IsAdmin) {
    getAllStationsAdmin(function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  } else {
    getAllStationsPassenger(function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  }
});

app.post("/api/station", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  var stopID = req.body.stopID;

  //can only view a specific station if admin
  if (req.session.IsAdmin) {
    getStation(stopID, function(result) {
      if (!result.valid) {
        res.send({"status" : "FAILURE", "reason" : result.reason});
        return;
      }
      res.send({"results" : result.results[0], "status" : "SUCCESS"})
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }
});

app.get("/api/trips", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  //can only see this screen as passenger
  if (!req.session.IsAdmin) {
    getTrips(req.session.user, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  } else {
    res.send({"valid": false, reason: "Must be a passenger"});
  }
})

app.post("/api/trips/filter", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  var start = req.body.startDate;
  var end = req.body.endDate; 
  if (start != "") {
    start = parseInt(start);
    
  }
  if (end != "") {
    end = parseInt(end);
  }

  if ((isNaN(start) || isNaN(end)) && (start != "" || end != "")) {
    res.send({"status" : "FAILURE", "reason" : "Invalid Date"});
    return;
  }
  if (start != "") {
    start = moment(start).format().toString();
  }
  if (end != "") {
    end = moment(end).format().toString();
  }

  //can only see this screen as passenger
  if (!req.session.IsAdmin) {
    getTripsFilter(req.session.user, start, end, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  } else {
    res.send({"valid": false, reason: "Must be a passenger"});
  }
})

app.post("/api/trips/create/start", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }
  req.session.IsAdmin = 0;

  var start = req.body.startsAt;
  var bn = req.body.BreezecardNum;
  var val = req.body.Value;

  if (req.session.IsAdmin == 0) {
    startTrip(val, bn, start, null, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"reason" : results.reason, "status" : "SUCCESS", "results" : results.results});
    })
  } else {
    res.send({"valid": false, reason: "Must be a passenger"});
  }
})

app.post("/api/trips/create/end", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  var start = req.body.startsAt;
  var bn = req.body.BreezecardNum;
  var end = req.body.endsAt;

  if (req.session.IsAdmin == 0) {
    endTrip(bn, start, end, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"reason" : results.reason, "status" : "SUCCESS"});
    })
  } else {
    res.send({"valid": false, reason: "Must be a passenger"});
  }
})

app.get("/api/trips/view", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  if (req.session.IsAdmin == 0) {
    checkTrip(req.session.user, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"endstations" : results.results, "trip" : results.trip, "status" : "SUCCESS", "reason" : results.reason});
    })
  } else {
    res.send({"valid": false, reason: "Must be a passenger"});
  }  
})

app.get("/api/conflicts", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  //can only see this page as admin
  if (req.session.IsAdmin) {
    getConflicts(function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }
})

app.get("/api/flow", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }
 
  //can only see this page as admin
  if (req.session.IsAdmin) {
    calculateFlow(function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }
})

app.post("/api/flow/filter", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"valid": false, reason: "Not logged in"});
    return;
  }

  var start = req.body.startDate;
  var end = req.body.endDate; 
  if (start != "") {
    start = parseInt(start);
    
  }
  if (end != "") {
    end = parseInt(end);
  }

  if ((isNaN(start) || isNaN(end)) && (start != "" || end != "")) {
    res.send({"status" : "FAILURE", "reason" : "Invalid Date"});
    return;
  }
  if (start != "") {
    start = moment(start).format().toString();
  }
  if (end != "") {
    end = moment(end).format().toString();
  }

  // start = moment.utc(start).format()
  // end = moment.utc(end).format();

  console.log(start);
  console.log(end);
  //can only see this page as admin
  if (req.session.IsAdmin) {
    calculateFlowFilter(start, end, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"results" : results.results, "status" : "SUCCESS"});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }
})

app.post("/api/station/create", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE", reason: "Not logged in"});
    return;
  } 

  var name = req.body.stationName;
  var stopID = req.body.stopID;
  var fee = req.body.fee;
  var type = req.body.type;
  var status = req.body.status;
  var intersection = req.body.intersection;

  //can only see this page as admin
  if (req.session.IsAdmin) {
    createStation(stopID, name, fee, status, type, intersection, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"status" : "SUCCESS", "reason" : results.reason});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }

})

app.post("/api/station/update", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE", reason: "Not logged in"});
    return;
  }

  var stopID = req.body.stopID;
  var fee = req.body.fee;
  var status = req.body.status == 'true' ? true : false;

  if (req.session.IsAdmin) {
    updateStation(stopID, fee, status, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"status" : "SUCCESS", "reason" : results.reason});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }  
})

app.post("/api/conflicts/owner", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE", reason: "Not logged in"});
    return;
  }

  var user = req.body.user;
  var numBreeze = req.body.breezecardnum;
  var old = req.body.old == "true" ? true : false; 

  if (req.session.IsAdmin) {
    updateCardOwner(user, numBreeze, old, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"status" : "SUCCESS", "reason" : results.reason});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }  
})

app.post("/api/breezecard/set_value", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE", reason: "Not logged in"});
    return;
  }

  var bn = req.body.BreezecardNum;
  var val = req.body.Value;

  if (req.session.IsAdmin) {
    setCardValue(val, bn, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"status" : "SUCCESS", "reason" : results.reason});
    })
  } else {
    res.send({"status" : "SUCCESS", reason: "Must be an admin"});
  }
})

app.post("/api/breezecard/transfer", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.send({"status": "FAILURE", reason: "Not logged in"});
    return;
  }

  var user = req.body.user;
  var bn = req.body.BreezecardNum;
  var old = false;

  if (req.session.IsAdmin) {
    updateCardOwner(user, bn, old, function(results) {
      if (!results.valid) {
        res.send({"status" : "FAILURE", "reason" : results.reason});
        return;
      }
      res.send({"status" : "SUCCESS", "reason" : results.reason});
    })
  } else {
    res.send({"valid": false, reason: "Must be an admin"});
  }  
})

app.get('/logout', function (req, res) {
    req.session.user = undefined;
    req.session.IsAdmin = undefined;
    res.redirect("/");
});

function checkCred(user, pass, callback) {
  if (typeof user === 'undefined' || typeof pass === 'undefined') {
    return callback({"valid": false, "reason": "Invalid Credentials"});
  }
  getUser(user, function(result) {
      if (result == null) {
        return callback({"valid": false, "reason": "User does not exist"});
      }
      var pass_hash = result.Password;
      bcrypt.compare(pass ,pass_hash, function(err, res) {
        //will return res of true if passwords are same
        if (err) {
          return callback({"valid": false, "reason": "Invalid Credentials"});
        }
        
        var newresult = {};
        if (res) {
          newresult = {"valid": true, "IsAdmin":result.IsAdmin}
        } else {
          newresult = {"valid": false, "reason": "Password Incorrect"};
        }
        return callback(newresult)
      });
  });
}

function checkAdmin(user, callback) {
  if (typeof user === 'undefined') {
    return callback(false);
  }
  getUser(user, function(result) {
    if (result.IsAdmin == 1) {
      return callback(true);
    }
    return callback(false);
  })
}

function getUser(user, callback) {
  if (typeof user === 'undefined') {
    return callback(null);
  }
  connection.execute(
    "select * from user where username = ?",
    [user],
    function(err, results, fields) {
      if (err || results.length == 0) {
        return callback(null);
      }
      return callback(results[0]);
    })
}

function hashPassword(pass, callback) {
  bcrypt.genSalt(saltRounds, function(err, salt) {
    bcrypt.hash(pass, salt, function(err, hash) {
      if (err) {
        return callback(true, null);
      }
      callback(null, pass)
    });
  });
}

app.post('/register', function(req, res) {
    var user = req.body.username;
    var pass = req.body.password;
    var email = req.body.email;
    var breezecard = req.body.breezecard;
    var needNewCard = req.body.needNewCard == "true" ? true : false;
    //make sure pass is right length
    if (pass.length < 8) {
      res.send({"status" : "FAILURE", "reason" : "Password must be eight or more characters"});
      return;
    }
    //check valid email
    if (!validator.isEmail(email)) {
       res.send({"status" : "FAILURE", "reason" : "Please enter a valid email address"});
      return;
    }
    //check breeze card is right length
    if (!needNewCard && breezecard.length != 16) {
      res.send({"status" : "FAILURE", "reason" : "Please enter a valid breezecard number"});
      return;
    }


    //new stuff
    /*
    async.waterfall([
      function(callback) {
        getUser(user, function(result) {
          if (result != null) {
            res.send({"status" : "FAILURE", "reason" : "User already exists"});
            callback(true);
            return;
          }
          callback(null)
        })
      },
      function(arg1, arg2, callback) {
          // arg1 now equals 'one' and arg2 now equals 'two'
          hashPassword(pass, callback);
      },
      function(arg1, callback) {
          // arg1 now equals 'three'
          callback(null, 'done');
          
      }
      ], function (err, result) {
          // result now equals 'done'
          if err == ''
      });
      */
    getUser(user, function(result) {
      if (result != null) {
        res.send({"status" : "FAILURE", "reason" : "User already exists"});
        return;
      }
      //now hash pass and store in DB
      bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(pass, salt, function(err, hash) {
            console.log(hash);
            connection.execute(
              //passed all fields, start putting into database wtih User table first
              "insert into user (Username, Password, IsAdmin) values (?, ?, ?)",
              [user, hash, 0],
              function(err, results, fields) {
                  if (err) {
                    res.send({"status" : "FAILURE", "reason" : "Error in inserting into Users"});
                    deleteUser(user);
                    return;
                  }
                  //now update Passenger table with new user and email
                  connection.execute(
                    "insert into Passenger (Username, Email) values (?, ?)",
                    [user, email],
                    function(err, results, fields) {
                      if (err) {
                        res.send({"status" : "FAILURE", "reason" : "Error in inserting into Passengers"});
                        deleteUser(user);
                        return; 
                      }
                      var newCard = randomstring.generate({
                        length: 16,
                        charset: 'numeric'
                      });
                      if (needNewCard) {
                        //enter newly generated breezecard
                        generateBreezecard(function(data) {
                          if (typeof data !== 'undefined') {
                            if (data.valid) {
                              connection.execute(
                                "insert into breezecard (BreezecardNum, BelongsTo) values (?, ?)", 
                                [data.results, user],
                                function(err, results, fields) {
                                  if (err) {
                                    res.send({"status" : "FAILURE", "reason" : "Error in inserting into Breezecard"});
                                    deleteUser(user);
                                    return; 
                                  }
                                  res.send({status: "SUCCESS", detail : "New Breezecard added without issues"});
                                  return;
                                });
                              
                            }
                          }
                        })
                      } else {
                        //begin checking breezecard
                        connection.execute(
                          "select * from breezecard where breezecardnum = ?",
                          [breezecard],
                          function(err, results, fields) {
                            if (err) {
                              res.send({"status" : "FAILURE", "reason" : "Error in selecting Breezecard"});
                              deleteUser(user);
                              return;
                            }
                            if (results.length == 0) {
                              connection.execute(
                                "insert into breezecard (BreezecardNum, BelongsTo) values (?, ?)", 
                                [breezecard, user],
                                function(err, results, fields) {
                                  if (err) {
                                    res.send({"status" : "FAILURE", "reason" : "Error in inserting into Breezecard"});
                                    deleteUser(user);
                                    return; 
                                  }
                                  res.send({status: "SUCCESS", detail : "Breezecard added without issues"});
                                  return;
                                });
      
                            }
                            //breezecard already exists have to make new card and create conflict
                            else {
                              var d = moment.utc();
                              connection.execute(
                                "insert into conflict (Username, BreezecardNum, DateTime) values (?, ?, ?)",
                                [user, breezecard, d.format()],
                                function(err, results, fields) {
                                  if (err) {
                                    res.send({"status" : "FAILURE", "reason" : "Error in inserting into conflict"});
                                    deleteUser(user);
                                    return; 
                                  }
                                  connection.execute(
                                    "insert into breezecard (BreezecardNum, BelongsTo) values (?, ?)",
                                    [newCard, user],
                                    function(err, results, fields) {
                                      if (err) {
                                        res.send({"status" : "FAILURE", "reason" : "Error in inserting into breezecard after making new card"});
                                        deleteUser(user)
                                        return; 
                                      }
                                      res.send({status: "SUCCESS", detail : "Random Breezecard added"});
                                      return;
                                    });
      
                                })
                            
                          }
                        })
                      }

                      
                  });
                  
                  
              });
        });
      });

    })
});


function deleteUser(username) {
    connection.execute("SET FOREIGN_KEY_CHECKS=0",
    [],
    function(err, results, fields) {

    
    connection.execute(
      "delete from passenger where username = ?",
      [username],
      function(err, results, fields) {
        connection.execute(
          "delete from breezecard where belongsto = ?",
          [username],
          function(err, results, fields) { 
            connection.execute(
              "delete from user where username = ?",
              [username],
              function(err, results, fields) {
                connection.execute(
                  "SET FOREIGN_KEY_CHECKS=1",
                  [],
                  function(err, results, f) {
                    console.log("deleted user");
                  }
                )
              }
            )
          }
        )
      }
    )
  }
)}


function generateBreezecard(callback) {
  var newCard = randomstring.generate({
    length: 16,
    charset: 'numeric'
  });
  connection.execute(
    "select * from breezecard where breezecardnum = ?",
    [newCard],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to check if breezecard exists already"});
      }
      else if (results.length == 0) {
        return callback({"valid" : true, "results" : newCard});
      }
      return generateBreezecard(callback);
    })
}

function getAllStationsAdmin(callback) {
  connection.execute(
    "select * from station",
    function(err, results, fields) {
      if (err || results.length == 0) {
        return callback({"valid" : false, "reason" : "Failed to get list of stations"});
      }
      return callback({"valid" : true, "results" : results});
    })
}

function getAllStationsPassenger(callback) {
  connection.execute(
    "select * from station where closedstatus = ?",
    [0],
    function(err, results, fields) {
      if (err || results.length == 0) {
        return callback({"valid" : false, "reason" : "Failed to get list of stations"});
      }
      return callback({"valid" : true, "results" : results});
    })
}

function createStation(stopID, name, fee, status, type, intersection, callback) {
  connection.execute(
    "insert into station (StopID, Name, EnterFare, ClosedStatus, IsTrain) values (?, ?, ?, ?, ?)",
    [stopID, name, fee, status, type],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to create new station"});
      }
      if (type == 0) {
        connection.execute(
          "insert into busstationintersection (StopID, Intersection) values (?, ?)",
          [stopID, intersection],
          function(err, results, fields) {
            if (err) {
              return callback({"valid" : false, "reason" : "Failed to create new bus station"});
            }
            return callback({"valid" : true, "reason" : "Succesfully created new bus station"});
          })
      } else {
        return callback({"valid" : true, "reason" : "Successfully created new station"});
      }
    })
}

function getStation(stopID, callback) {
  connection.execute(
    "select * from ((station s) LEFT OUTER JOIN (busstationintersection b) ON s.StopID = b.StopID) where s.StopID = ?",
    [stopID],
    function(err, result, fields) {
      if (err || result.length == 0) {
        return callback({"valid" : false, "reason" : "Failed to get specific station"});
      }
      return callback({"valid" : true, "results" : result});
    })
}


function updateStation(stopID, fee, status, callback) {
  fee = parseFloat(fee)
  if (fee < 0 || fee > 50 || typeof fee === 'undefined') {
    return callback({"valid" : false, "reason" : "Must enter a fare between $0.00 and $50.00"});
  }
  connection.execute(
    "update station set EnterFare = ?, ClosedStatus = ? where StopID = ?",
    [fee, status ? 1 : 0, stopID],
    function(err, result, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to update station"});
      }
      return callback({"valid" : true, "reason" : "Successfully updated station"});
    })
}


function getConflicts(callback) {
  connection.execute(
    "select s.BreezecardNum as BN, c.Username as New, s.BelongsTo as Old, c.DateTime as DT from ((conflict c) LEFT OUTER JOIN (breezecard s) ON c.BreezecardNum = s.BreezecardNum)",
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to get list of conflicts"});
      }
      return callback({"valid" : true, "results" : results});
    })
}

function updateCardOwner(user, numBreeze, old, callback) {
  if (old) {
    connection.execute(
      "delete from conflict where breezecardnum = ?",
      [numBreeze],
      function(err, result, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to remove conflicts"});
        }
        return callback({"valid" : true, "reason" : "Completed update of card owner and removal of conflicts"});
      })
  } else {
    connection.execute("select BelongsTo from breezecard where BreezecardNum = ?",
    [numBreeze], function(err, results, fields) {
      if (err) {
        console.log("fix failed");
        return callback({"valid" : false, "reason" : "Failed to get card owner"});

      }
      var oldOwner = results[0].BelongsTo;
      console.log("OLLLLLD");
      console.log(oldOwner);
      connection.execute(
        "update breezecard set BelongsTo = ? where BreezecardNum = ?",
        [user, numBreeze],
        function(err, results, fields) {
          if (err) {
            return callback({"valid" : false, "reason" : "Failed to update card owner"});
          }
          connection.execute(
            "delete from conflict where breezecardnum = ?",
            [numBreeze],
            function(err, result, fields) {
              if (err) {
                return callback({"valid" : false, "reason" : "Failed to remove conflicts"});
              }

              checkUserBreezecards(oldOwner, function(data) {
                console.log("Added new card");
                console.log(data.reason);
                return callback({"valid" : true, "reason" : "Completed update of card owner and removal of conflicts"});
                
              })
              
            })
        })


    })
    
  }
}

function getBreezecards(callback) {
  connection.execute(
    "select * from breezecard",
    function(err, results, fields) {
      if(err) {
        return callback({"valid" : false, "reason" : "Failed to get list of breezecards"});
      }
      return callback({"valid" : true, "results" : results});
    })
}

function filterBreezecards(user, numBreeze, lower, upper, suspended, callback) {
  var qs = "select * from breezecard b where BelongsTo like ?  and BreezecardNum like ? and (Value like ? or Value > ?) and (Value like ? or Value < ?) and (NOT EXISTS (Select BreezecardNum from conflict c where c.BreezecardNum = b.BreezecardNum) OR ? = true)"

  connection.execute(
    qs,
    [user, numBreeze, lower,lower,upper, upper, suspended ? 1 : 0],
    function(err, results, fields) {
      if(err) {
        return callback({"valid" : false, "reason" : "Failed to get list of breezecards"});
      }
      return callback({"valid" : true, "results" : results});
    })
}

function setCardValue(value, numBreeze, callback) {
  if (value < 0 || value > 1000) {
    return callback({"valid" : false, "reason" : "New card value exceeds limit of $1000"});
  }
  connection.execute(
    "update breezecard set Value = ? where BreezecardNum = ?",
    [value, numBreeze],
    function(err, result, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to set new card value"});
      }
      return callback({"valid" : true, "reason" : "Successfully set new card value"});
    })
}

function getUserBreezecards(user, callback) {
  connection.execute(
    "select * from breezecard where BelongsTo = ? AND BreezecardNum NOT IN (select BreezecardNum from conflict)",
    [user],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to get list of users breezecards"});
      }
      return callback({"valid" : true, "results" : results});
    })
}


function removeCardFromUser(numBreeze, callback) {
  connection.execute(
    "update breezecard set BelongsTo = ? where BreezecardNum = ?",
    [null, numBreeze],
    function(err, result, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to remove breezecard"});
      }
      return callback({"valid" : true, "reason" : "Successfully removed breezecard"});
    })
}

function addBreezecard(numBreeze, user, callback) {
  if (numBreeze.length != 16) {
    return callback({"valid" : false, "reason" : "Invalid Breezecard Entered"});
  }
  connection.execute(
    "select * from breezecard where BreezecardNum = ?",
    [numBreeze],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to check if breezecard exists already"});
      }
      if (results.length == 0) {
        connection.execute(
          "insert into breezecard (BreezecardNum, BelongsTo) values (?, ?)",
          [numBreeze, user],
          function(err, result, fields) {
            console.log(err);
            if (err) {
              return callback({"valid" : false, "reason" : "Failed to add new breezecard"});
            }
            return callback({"valid" : true, "reason" : "Successfully added new breezecard"});
          })
        } else if (results[0].BelongsTo != null) {
          if (results[0].BelongsTo == user) {
            return callback({"valid" : false, "reason" : "Already own breezecard!"});
          }
          var d = moment.utc();
          connection.execute(
            "insert into conflict (Username, BreezecardNum, DateTime) values (?, ?, ?)",
            [user, numBreeze, d.format()],
            function(err, result, fields) {
              if (err) {
                return callback({"valid" : false, "reason" : "Failed to insert new conflict"});
              }
              return callback({"valid" : true, "reason" : "Created new conflict"});
            })
        } else {
        connection.execute(
          "update breezecard set BelongsTo = ? where BreezecardNum = ?",
          [user, numBreeze],
          function(err, result, fields) {
            if (err) {
              return callback({"valid" : false, "reason" : "Failed to update new owner for existing breezecard"});
            }
            return callback({"valid" : true, "reason" : "Updated owner for existing breezecard"});
          });
        }
    })
}

function updateCardValue(numBreeze, value, callback) {
  connection.execute(
    "select Value from breezecard where BreezecardNum = ?",
    [numBreeze],
    function(err, result, fields) {
      if (err) {
        return callback(false);
      }
      // if (isNaN(parseInt(newValue))) {
      //   return callback({"valid" : false, "reason" : "New value not a number"});
      // }
      var nv = 0
      try {
        value = parseFloat(value)
        nv = parseFloat(result[0].Value)
      }
      catch(err) {
        return callback({"valid" : false, "reason" : "New value not an int"});        
      }
      var newValue = nv + value;
      if (newValue > 1000 || value < 0) {
        return callback({"valid" : false, "reason" : "New value exceeds limit of $1000"});
      }
      connection.execute(
        "update breezecard set value = ? where BreezecardNum = ?",
        [newValue, numBreeze],
        function(err, results, fields) {
          if (err) {
            return callback({"valid" : false, "reason" : "Failed to update new breezecard value"});
          }
          return callback({"valid" : true, "reason" : "Successfully updated new breezecard value"});
        }) 
    })
}

function getTrips(user, callback) {
  connection.execute(
    `Select t.Tripfare, s1.Name as Start, s2.Name as Ending, t.BreezecardNum, t.StartTime 
    from ((trip t LEFT OUTER JOIN station s1 ON t.StartsAt = s1.StopID) LEFT OUTER JOIN station s2 ON t.EndsAt = s2.StopID) 
    where breezecardnum in (select breezecardnum from breezecard where belongsto = ? AND breezecardnum NOT IN (select BreezecardNum from conflict))`.toString(),
    [user],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to get trip history"});
      }
      return callback({"valid" : true, "results" : results});
    })
}

function getTripsFilter(user, start, end, callback) {
  if (start == "" && end == "") {
    return getTrips(user, callback);
  } else if (start == "") {
    connection.execute(
      `Select t.Tripfare, s1.Name as Start, s2.Name as Ending, t.BreezecardNum, t.StartTime 
      from ((trip t LEFT OUTER JOIN station s1 ON t.StartsAt = s1.StopID) LEFT OUTER JOIN station s2 ON t.EndsAt = s2.StopID) 
      where starttime < ? AND breezecardnum in (select breezecardnum from breezecard where belongsto = ? AND breezecardnum NOT IN (select BreezecardNum from conflict))`.toString(),
      [end, user],
      function(err, results, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to get trip history with no start input"});
        }
        return callback({"valid" : true, "results" : results});
      })
  } else if (end == "") {
    connection.execute(
      `Select t.Tripfare, s1.Name as Start, s2.Name as Ending, t.BreezecardNum, t.StartTime 
      from ((trip t LEFT OUTER JOIN station s1 ON t.StartsAt = s1.StopID) LEFT OUTER JOIN station s2 ON t.EndsAt = s2.StopID) 
      where starttime > ? AND breezecardnum in (select breezecardnum from breezecard where belongsto = ? AND breezecardnum NOT IN (select BreezecardNum from conflict))`.toString(),
      [start, user],
      function(err, results, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to get trip history with no end input"});
        }
        return callback({"valid" : true, "results" : results});
      })
  } else {
    connection.execute(
      `Select t.Tripfare, s1.Name as Start, s2.Name as Ending, t.BreezecardNum, t.StartTime 
      from ((trip t LEFT OUTER JOIN station s1 ON t.StartsAt = s1.StopID) LEFT OUTER JOIN station s2 ON t.EndsAt = s2.StopID) 
      where starttime > ? AND starttime < ? AND breezecardnum in (select breezecardnum from breezecard where belongsto = ? AND breezecardnum NOT IN (select BreezecardNum from conflict))`.toString(),
      [start, end, user],
      function(err, results, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to get trip history"});
        }
        return callback({"valid" : true, "results" : results});
      })
  }
}

function startTrip(value, numBreeze, start, end, callback) {
  connection.execute(
    "select enterfare, istrain from station where stopid = ?",
    [start],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to get station fare cost"});
      }
      var val = parseFloat(value);
      var fare = parseFloat(results[0].enterfare);
      var type = parseInt(results[0].istrain);
      if (val < fare) {
        return callback({"valid" : false, "reason" : "Not enough balance on card for this trip"});
      }
      var d = moment.utc();
      connection.execute(
        "insert into trip (Tripfare, StartTime, BreezecardNum, StartsAt, EndsAt) values (?, ?, ?, ?, ?)",
        [fare, d.format(), numBreeze, start, end],
        function(err, results, fields) {
          if (err) {
            return callback({"valid" : false, "reason" : "Failed to start a new trip"});
          }
          var newBalance = val - fare;
          connection.execute(
            "update breezecard set value = ? where BreezecardNum = ?",
            [newBalance, numBreeze],
            function(err, results, fields) {
              if (err) {
                return callback({"valid" : false, "reason" : "Failed to deduct trip fare from breezecard"});
              }
              connection.execute(
                "select * from station where istrain = ? AND closedstatus = ? AND stopID != ?",
                [type, 0, start],
                function(err, results, fields) {
                  if (err) {
                    return callback({"valid" : false, "reason" : "Failed to get list of options available for end"});
                  }
                  return callback({"valid" : true, "reason" : "Successfully started a new trip and deducted from breezecard", "results" : results});
                })
            })
        })
    })
}

function endTrip(numBreeze, start, end, callback) {
  connection.execute(
    "update trip set EndsAt = ? where BreezecardNum = ? AND StartsAt = ? AND EndsAt is NULL",
    [end, numBreeze, start],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to insert new trip"});
      }
      return callback({"valid" : true, "reason" : "Added ending station to trip"});
    })
}

function checkTrip(user, callback) {
  connection.execute(
    "select * from (trip t JOIN station s on t.StartsAt = s.StopID) where breezecardnum in (select breezecardnum from breezecard where belongsto = ?) AND EndsAt is NULL", 
    [user],
    function(err, results, fields) {
      if (err) {
        return callback({"valid" : false, "reason" : "Failed to check if user is already on a trip"});
      }
      if (results.length != 0) {
        var stopID = results[0].StartsAt;
        var trip = results;
        connection.execute(
          "select * from station where istrain in (select istrain from station where stopID = ?) AND closedstatus = ? AND stopID != ?",
          [stopID, 0, stopID],
          function(err, results, fields) {
            if (err) {
              return callback({"valid" : false, "reason" : "Failed to get list of options available for end"});
            }
            return callback({"valid" : true, "reason" : "Successfully got active trip and list of options for end station", "results" : results, "trip" : trip});
          })
      } else {
        return callback({"valid" : true, "reason" : "User is currently not on a trip", "results" : results, trip: false});
      }
    })
}

function checkUserBreezecards(user, callback) {
  console.log("reached");
  getUserBreezecards(user, function(results) {
    if (!results.valid) {
      return callback(results);
    }
    if (results.results.length == 0) {
      generateBreezecard(function(result) {
        if (!result.valid) {
          return callback(result);
        }
        addBreezecard(result.results, user, callback);
      })
    } else {
      return callback(results);
    }
  })
}

function calculateFlow(callback) {
  connection.execute(
    `Select s.Name,  t1.revenue, t2.pout, t1.pin 
    FROM (
      (((Select StopID, Name from Station) s)  LEFT OUTER JOIN
      ((SELECT StopID, Name,  SUM(Tripfare) as revenue, COUNT(StopID) as pin 
      FROM (station JOIN trip ON StartsAt =  StopID)
      GROUP BY StopID) t1) 
        ON s.StopID = t1.StopID)
      LEFT OUTER JOIN (
      SELECT StopID, COUNT(StopID) as pout 
        FROM (station JOIN trip ON EndsAt =  StopID)
        GROUP BY StopID) t2 ON t1.StopID = t2.StopID)`.toString(),
      function(err, results, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to calculate flow"});
        }
        return callback({"valid" : true, "results" : results});
      })
}

function calculateFlowFilter(start, end, callback) {
  if (start == "" && end == "") {
    return calculateFlow(callback);
  } else if (start == "") {
    connection.execute(
    `Select s.Name,  t1.revenue, t2.pout, t1.pin 
    FROM (
      (((Select StopID, Name from Station) s)  LEFT OUTER JOIN
      ((SELECT StopID, Name,  SUM(Tripfare) as revenue, COUNT(StopID) as pin 
      FROM (station JOIN trip ON StartsAt =  StopID)
      WHERE StartTime < ?
      GROUP BY StopID) t1) 
        ON s.StopID = t1.StopID)
      LEFT OUTER JOIN (
      SELECT StopID, COUNT(StopID) as pout 
        FROM (station JOIN trip ON EndsAt =  StopID)
        WHERE StartTime < ?
        GROUP BY StopID) t2 ON t1.StopID = t2.StopID)`.toString(),
      [end, end],
      function(err, results, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to calculate flow with no start input"});
        }
        return callback({"valid" : true, "results" : results});
      })
  } else if (end == "") {
    connection.execute(
    `Select s.Name,  t1.revenue, t2.pout, t1.pin 
    FROM (
      (((Select StopID, Name from Station) s)  LEFT OUTER JOIN
      ((SELECT StopID, Name,  SUM(Tripfare) as revenue, COUNT(StopID) as pin 
      FROM (station JOIN trip ON StartsAt =  StopID)
      WHERE StartTime > ? 
      GROUP BY StopID) t1) 
        ON s.StopID = t1.StopID)
      LEFT OUTER JOIN (
      SELECT StopID, COUNT(StopID) as pout 
        FROM (station JOIN trip ON EndsAt =  StopID)
        WHERE StartTime > ?
        GROUP BY StopID) t2 ON t1.StopID = t2.StopID)`.toString(),
      [start, start],
      function(err, results, fields) {
        if (err) {
          return callback({"valid" : false, "reason" : "Failed to calculate flow with no end input"});
        }
        return callback({"valid" : true, "results" : results});
      })
  } else {
    connection.execute(
      `Select s.Name,  t1.revenue, t2.pout, t1.pin 
      FROM (
        (((Select StopID, Name from Station) s)  LEFT OUTER JOIN
        ((SELECT StopID, Name,  SUM(Tripfare) as revenue, COUNT(StopID) as pin 
        FROM (station JOIN trip ON StartsAt =  StopID)
        WHERE StartTime > ? AND StartTime < ?
        GROUP BY StopID) t1) 
          ON s.StopID = t1.StopID)
        LEFT OUTER JOIN (
        SELECT StopID, COUNT(StopID) as pout 
          FROM (station JOIN trip ON EndsAt =  StopID)
          WHERE StartTime > ? AND StartTime < ?
          GROUP BY StopID) t2 ON t1.StopID = t2.StopID)`.toString(),
        [start, end, start, end],
        function(err, results, fields) {
          if (err) {
            return callback({"valid" : false, "reason" : "Failed to calculate flow"});
          }
          return callback({"valid" : true, "results" : results});
        })
  }
}

app.get('/login', function(req,res) {
  if (typeof req.session.user !== 'undefined') {
    res.redirect("/session");
  }
  else {
    res.sendFile(path.join(__dirname, "html/login.html"));
  }

});


app.get("/", function(req, res) {
  res.sendFile(path.join(__dirname, "html/index.html"));
})

app.get("/signup", function(req, res) {
  
  res.sendFile(path.join(__dirname, "html/signup.html"));

})

app.get("/session/passenger/breezecards", function(req, res) {
  // debug
  // req.session.user = "dd";
  // req.session.IsAdmin = 0;
  //=debug

  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 1) {
    res.redirect("/session/admin");
  }
  else {
    res.sendFile(path.join(__dirname, "html/BC_management_passenger.html"));
  }
})

app.get("/session", function(req, res) {
    res.render('session', {name: req.session.user, page: "Home"});
})

//admin pages -------
app.get("/session/admin/stn-mgmt", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 1) {
    res.sendFile(path.join(__dirname, "html/stn-mgmt.html"));
  }
  else {
    res.redirect("/session/passenger");
  }
})
app.get("/session/admin/susp-card", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 1) {
    res.sendFile(path.join(__dirname, "html/susp-card.html"));
  }
  else {
    res.redirect("/session/passenger");
  }
})
app.get("/session/admin/BC-mgmt", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 1) {
    res.sendFile(path.join(__dirname, "html/BC-mgmt.html"));
  }
  else {
    res.redirect("/session/passenger");
  }
})
app.get("/session/admin/PassFlowReport", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 1) {
    res.sendFile(path.join(__dirname, "html/PassFlowReport.html"));
  }
  else {
    res.redirect("/session/passenger");
  }
});
//admin pages / 

//USER PAGES --
app.get("/session/passenger/trip_history", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 0) {
    res.sendFile(path.join(__dirname, "html/view-trip-history.html"));
  }
  else {
    res.redirect("/");
  }
});


app.get("/session/passenger/manage_trip", function(req, res) {
  if (typeof req.session.user === 'undefined') {
    res.redirect("/");
  }
  else if (req.session.IsAdmin == 0) {
    res.sendFile(path.join(__dirname, "html/trip.html"));
  }
  else {
    res.redirect("/");
  }
});


server.listen(port, function () {
  console.log("server running on port: " + port.toString())
})