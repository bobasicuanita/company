////////////////// Requiring all Dependencies ///////////////////////////
require('dotenv').config()
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const _ = require("lodash");
const multer = require("multer");
const fs = require("fs");
const path = require('path');
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const cookieParser = require("cookie-parser");
const async = require('async');
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const flash = require("connect-flash");
const moment = require("moment");

////////////////// Setting up all Middleware ///////////////////////////

const app = express();

const fileStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads');
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});

const fileFilter = function(req, file, cb) {
  if (file.mimetype === 'application/octet-stream') {
    cb(null, true);
  } else {
    cb(null, false);
  }
};

app.set('view engine', 'ejs');

app.use(cookieParser());

app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));

app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false
}));

app.use(flash());

app.use(passport.initialize());
app.use(passport.session());


app.use(multer({storage : fileStorage, fileFilter:fileFilter}).single('fileOne'));

////////////////// Connecting to MongoDB Database ///////////////////////////

mongoose.connect("mongodb+srv://admin-konstantinos:sikuanita02@cluster0-p6pal.mongodb.net/companyDB", {useNewUrlParser: true});
mongoose.set('useCreateIndex', true);

////////////////// Creating Mongoose Schemas for the database ///////////////////////////

const Schema = mongoose.Schema;

//// Schema for Users ////

const userSchema = new Schema ({
  username: { type: String, required: true, unique: true },
  password: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

userSchema.plugin(passportLocalMongoose);

//// Schema for HISTORY LOG statements ////

const logSchema = new Schema ({
  type: String,
  date: Date,
  from: String,
  comment: String,
  amount: Number
});

//// Schema for charging statements ////

const chargeSchema = new Schema ({
  type: String,
  date: Date,
  from: String,
  comment: String,
  amount: Number
});

const fuelSchema = new Schema ({
  type: String,
  date: Date,
  from: String,
  comment: String,
  amount: Number
});


const fileSchema = new Schema ({
  name: String,
  path: String
});


//// declaring Models  ////

const User = new mongoose.model("User", userSchema);
const Log = mongoose.model("Log", logSchema);
const Charge = mongoose.model("Charge", chargeSchema);
const Fuel = mongoose.model("Fuel", fuelSchema);
const Filedetail = mongoose.model("Filedetail", fileSchema);

//// Local Strategy ////

passport.use(User.createStrategy());
 
passport.serializeUser(function(user,done){
  done(null,user);
});

passport.deserializeUser(function(user,done){
  done(null,user);
});


//////////////////////////////////////    HTTP Requests   //////////////////////////////////////////

////////////    HTTP Get & Post Requests for Home Route     //////////////

app.get("/", function(req, res) {
  if (req.isAuthenticated()) {
    res.redirect("/log");
  } else {
    res.render("home", {errorMessage: req.flash("error")});
  }
});

////////////////   User Register ///////////////////

// app.post("/register", function(req, res) {
//   if (req.body.password.length < 8) {
//     req.flash("error","Απαιτούνται τουλάχιστον 8 χαρακτήρες για τον κωδικό!");
//     res.redirect("/");
//   } else {
//     User.register({username: req.body.username}, req.body.password, function(err, user) {
//       if(err) {
//         req.flash("error","Το e-mail που χρησιμοποιήσατε χρησιμοποιήτε ήδη.");
//         res.redirect("/");
//     } else {
//         passport.authenticate("local")(req, req, function() {
//         res.redirect("/log/1");
//       });
//     }
//   })
//   }
// });

////////////////   User login ///////////////////

app.post("/login", function(req, res) {
  const user = new User ({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {         /// bug how to return "no username specified" & "Username does not exists" instead of Anauthorized?
        if (req.body.rememberme) {
          req.session.cookie.originalMaxAge = 30 * 24 * 60 * 60 * 1000; // Cookie expires after 30 days
        } else {
          req.session.cookie._expires = false; // Cookie expires at end of session
        }
          res.redirect("/log/1");
      });
    }
  });
});

////////////////   User logout ///////////////////

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

////////////////   forgot password page GET request ///////////////////

app.get("/forgot", function(req, res ) {
  res.render("forgot", {errorMessage: req.flash("error"),infoMessage: req.flash("info")});
}); 


////////////////   Post request to generate token and email it ///////////////////

app.post("/forgot", function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buffer) {
        let token = buffer.toString('hex');
        done(err, token);
    });
  },
  function(token, done) {
    User.findOne({ username: req.body.username }, function(err, user) {
      if(!user) {
          req.flash("error","Δεν υπάρχει λογαριασμός με αυτό το E-mail!");
          res.redirect("/forgot");
      } else {
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() +360000;

        user.save(function(err) {
          done(err, token, user);
        });
      }
    });
  },
    function(token, user, done) {
      let transporter = nodemailer.createTransport({
        service: "Hotmail",
        auth: {
         user: process.env.EMAIL,
         pass: process.env.EMAIL_PASS
       },
     });

      let mailOptions = {
        to: req.body.username,
        from: "kkmetafores@hotmail.com",
        subject: "KK Μεταφορές - Επαναφορά Κωδικού",
        text: "Λάβατε αυτο το email γιατί εσείς ή κάποιος άλλος έκανε αίτηση επαναφοράς κωδικού για τον λογαριασμό σας.\n\n" +
        "Παρακαλώ, κάντε κλίκ στον σύνδεσμο που ακολουθεί, ή κάντε τον επικόλληση στον browser σας για να ολοκληρώσετε την διαδικασία:\n\n" +
        "http://" + req.headers.host + "/reset/" + token + "\n\n" +
        "Άν δεν κάνατε εσείς την αίτηση, παρακαλω αγνοήστε το παρόν email και ο κωδικός σας δεν θα αλλαχτεί.\n"
      };

      transporter.sendMail(mailOptions, function(err) {
          req.flash("info", "Αποστάλθηκε e-mail στο " + user.username + " με περαιτέρω οδηγίες.");
          res.redirect("/forgot");
          done(err, "done");
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect("/forgot");
  });
});

////////////////   Token link GET Request ///////////////////

app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error','Ο κωδικός επαναφοράς δεν είναι έγκυρος ή έχει λήξει.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      errorMessage: req.flash("error"),token:req.params.token
    });
  });
});

////////////////   Set new password after getting token via email ///////////////////

app.post("/reset/:token", function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if(!user) {
          req.flash("error", "Η επαναφορά κωδικού δεν είναι σωστή ή έχει λήξει.");
         res.redirect("/reset/" + req.params.token);
         }
         user.resetPasswordToken = undefined;
         user.resetPasswordExpires = undefined;

         user.setPassword(req.body.password, function() {
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
         });
      });
    },
    function(user, done) {
       let transporter = nodemailer.createTransport({
         service: "Hotmail",
         auth: {
          user: process.env.EMAIL,
          pass: process.env.EMAIL_PASS
        },
      });

       let mailOptions = {
          to: user.username,
          from: "kkmetafores@hotmail.com",
          subject: 'Ο κωδικός σας έχει αλλαχτεί.',
          text: 'Γεία σας,\n\n' +
           'Σας επιβεβαιώνουμε ότι ο κωδικός σας για το ' + user.username + ' έχει αλλάξει.\n'
       };

       transporter.sendMail(mailOptions, function(err) {
          done(err);
       });
      }
    ], function(err) {
      res.redirect('/');
    });
});

///////////////////////////   Profile Settings GET & POST Requests //////////////////////////////

app.get("/profile/:userid", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("profile", {userid:req.user._id, errorMessage:req.flash("error"), infoMessage:req.flash("info")});
  } else {
    req.flash("error", "Παρακαλώ συνδεθείτε/Εγγραφείτε.")
    res.redirect("/");
  }
});

////////////////   Password change POST REQUEST ///////////////////

app.post("/profile/:userid", function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({_id: req.params.userid}, function(err, user) {
       if(!user) {
          req.flash("error", "Δεν βρέθηκε ο χρήστης!");
          res.redirect("/profile/" + req.params.userid);
       }

        user.changePassword(req.body.oldPassword, req.body.newPassword, function(err, user) {
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
         });
      });
         },
         function(user, done) {
          let transporter = nodemailer.createTransport({
            service: "Hotmail",
            auth: {
             user: process.env.EMAIL,
             pass: process.env.EMAIL_PASS
           },
         });
   
          let mailOptions = {
             to: user.username,
             from: "kkmetafores@hotmail.com",
             subject: 'Ο κωδικός σας έχει αλλαχτεί.',
             text: 'Γεία σας,\n\n' +
              'Σας επιβεβαιώνουμε ότι ο κωδικός που θέσατε για το ' + user.username + ' έχει αλλάξει.\n'
          };
   
          transporter.sendMail(mailOptions, function(err) {
             done(err);
          });
         }
       ],function(err) {
          console.log(err);
          req.flash("info", "Ο Κωδικός άλλαξε επιτυχώς!");
          res.redirect('/profile/:userid');
      });
});

////////////    HTTP Get & Post Requests for /log Route     //////////////

app.route("/log/:page")

  .get(function(req, res) {
    if (req.isAuthenticated()) {

      let perPage = 10;
      let page = req.params.page || 1;

      Log.find({}).sort({date: 'desc'}).limit(perPage * page).exec(function(err, found) {
        Log.countDocuments().exec(function(err, count) {
          if(!err) {
            let dates = [];
            found.forEach(function(found) {
              let formattedDate = moment(found.date).format("L");
              dates.push(formattedDate);
            });
            res.render("logs", {
              logStatements:found,
              userid:req.user._id,
              formattedDates:dates,
              page:page,
              pages: Math.ceil(count / perPage)
            });

          } else {
            res.send(err);
          }
        });
      });
    } else {
      req.flash("error", "Παρακαλώ συνδεθείτε/Εγγραφείτε.")
      res.redirect("/");
    }
  })

  .post(function(req, res) {
    const newLog = new Log({
      type: req.body.type,
      date: req.body.date,
      from: req.body.from,
      comment: req.body.comment,
      amount: req.body.amount
    });

    newLog.save(function(err) {
      if (!err) {
        res.redirect("/log/1");
      } else {
        res.send(err);
      }
    })
  });

////////////    HTTP Delete Request for /log Route    //////////////


app.post("/deletelog", function(req, res) {
      Log.deleteOne({_id: req.body.id}, function(err) {
        if(!err) {
          res.redirect("/log");
        } else {
          res.send(err);
        }
      })
    });


// ////////////     HTTP Post - Filter Request for /log Route     //////////////

// app.post("/filter", function(req, res) {
//   const checked = req.body.checkbox;

//   if (checked === "Έσοδo" || checked ==="Έξοδo") {
//     Log.find({type: checked}).sort({date: 'desc'}).exec(function(err, found) {
//       if(!err) {
//         let dates = [];
//         found.forEach(function(found) {
//           let formattedDate = moment(found.date).format("L");
//           dates.push(formattedDate);
//         });
//         res.render("logs", {logStatements:found, userid:req.user._id, formattedDates:dates});
//       } else {
//         res.send(err);
//       }
//     })
//   } else if (checked === "Εταιρεία" || checked === "SDS") {
//     Log.find({from: checked}).sort({date: 'desc'}).exec(function(err, found) {
//       if (!err) {
//         let dates = [];
//         found.forEach(function(found) {
//           let formattedDate = moment(found.date).format("L");
//           dates.push(formattedDate);
//         });
//         res.render("logs", {logStatements: found, userid:req.user._id, formattedDates:dates});
//       } else {
//         res.send(err);
//       }
//     })
//   } else {
//     Log.find({comment: checked}).sort({date: 'desc'}).exec(function(err, found) {
//       if (!err) {
//         let dates = [];
//         found.forEach(function(found) {
//           let formattedDate = moment(found.date).format("L");
//           dates.push(formattedDate);
//         });
//         res.render("logs", {logStatements: found, userid:req.user._id, formattedDates:dates});
//       } else {
//         res.send(err);
//       }
//     })
//   }
// });

////////////    HTTP Requests for Customers Route     //////////////

app.get("/customers/:customerName/",function(req, res) {
  if (req.isAuthenticated()) {
    
    const customerName = _.upperCase(req.params.customerName);
    
    let dates = [];
    let sdsPayments = [];
    let chargeDates = [];
    let chargeamounts = [];

    let perPage = 5;
    let log = req.query.log || 1;
    let chargepage = req.query.charge || 1;

    Log.find({}, function(err, totallogs) {
      totallogs.forEach(function(log) {
        if (log.type == 'Έσοδo') {
          sdsPayments.push(log.amount);
        }
      });
    }),

    Charge.find({}, function(err, totalcharges) {
      totalcharges.forEach(function(charge) {
        chargeamounts.push(charge.amount);
      });
    }),

    Log.find({from:customerName}).sort({date: 'desc'}).limit(perPage * log).exec(function(err, foundlogs) {
      Log.countDocuments({from:customerName}).exec(function(err, countLogs) {
      if (!err) {
        foundlogs.forEach(function(log) {
          let formattedLogDate = moment(log.date).format("L");
          dates.push(formattedLogDate);
        });
        Charge.find({}).sort({date: 'desc'}).limit(perPage * chargepage).exec(function(err, foundcharges) {
          Charge.countDocuments().exec(function(err, countCharges) {
          if (!err) {
            foundcharges.forEach(function(charge) {
              let formattedChargeDate = moment(charge.date).format("L");
              chargeDates.push(formattedChargeDate);
            });


            const reducer = (accumulator, currentValue) => accumulator + currentValue;
            let turnover =  chargeamounts.reduce(reducer);
            let income = sdsPayments.reduce(reducer);

            res.render("customers", {
                logStatements: foundlogs,
                chargeStatements:foundcharges,
                userid:req.user._id,
                formattedLogDates:dates,
                formattedChargeDate:chargeDates,
                turnover:turnover,
                income:turnover,
                log:log,
                chargepage:chargepage,
                logPages: Math.ceil(countLogs / perPage),
                chargePages: Math.ceil(countCharges / perPage)
            });
          } else {
            res.send(err);
          }
        });
       })
      } else {
          res.send(err);
      }
    });
    })
  } else {
    req.flash("error", "Παρακαλώ συνδεθείτε/Εγγραφείτε.")
    res.redirect("/");
  }
});

app.post("/customers", function(req, res) {
  const newCharge = new Charge({
    type: req.body.type,
    date: req.body.date,
    from: req.body.from,
    comment: req.body.comment,
    amount: req.body.amount
  });

  newCharge.save(function(err) {
    if (!err) {
      res.redirect("/customers/" + req.body.from);
    } else {
      res.send(err);
    }
  })
});

app.post("/deletecustomer", function(req, res) {
      Charge.deleteOne({_id: req.body.id}, function(err) {
        if(!err) {
          res.redirect("customers/SDS");
        } else {
          res.send(err);
        }
      })
    });

//////////////     HTTP Requests for Fuel Route     //////////////

app.get("/fuel/",function(req, res) {
  if (req.isAuthenticated()) {

    let dates = [];
    let fueldates = [];
    let fuelPayments = [];
    let fuelCharges = [];

    let perPage = 5;
    let log = req.query.log || 1;
    let fuelChargepage = req.query.fuelcharge || 1;

    Log.find({}, function(err, totallogs) {
      totallogs.forEach(function(log) {
        if (log.comment == 'Καύσιμα') {
          fuelPayments.push(log.amount);
        }
      });
    }),

    Fuel.find({}, function(err, fuelcharges) {
      fuelcharges.forEach(function(fuel) {
        fuelCharges.push(fuel.amount);
      });
    }),


    Log.find({comment:"Καύσιμα"}).sort({date: 'desc'}).limit(perPage * log).exec(function(err, foundlogs) {
      Log.countDocuments({comment:"Καύσιμα"}).exec(function(err, countLogs) {
      if (!err) {
        foundlogs.forEach(function(log) {
          let formattedLogDate = moment(log.date).format("L");
          dates.push(formattedLogDate);
        });
        Fuel.find({}).sort({date: 'desc'}).limit(perPage * fuelChargepage).exec(function(err, foundFuel) {
          Fuel.countDocuments().exec(function(err, countFuelCharges) {
          if (!err) {
            foundFuel.forEach(function(fuel) {
              let formattedFuelDate = moment(fuel.date).format("L");
              fueldates.push(formattedFuelDate);
            });

            const reducer = (accumulator, currentValue) => accumulator + currentValue;
            let fuelChargesTotal =  fuelCharges.reduce(reducer);
            let allPayments = fuelPayments.reduce(reducer);

           res.render("fuel", {
             logStatements: foundlogs,
             fuelStatements:foundFuel,
             userid:req.user._id,
             formattedFuelDates:fueldates,
             formattedLogDates:dates,
             fuelChargesTotal:fuelChargesTotal,
             allPayments:allPayments,
             log:log,
             fuelChargepage:fuelChargepage,
             logPages: Math.ceil(countLogs / perPage),
             fuelPages: Math.ceil(countFuelCharges / perPage)
            });
          } else {
           res.send(err);
          }
       });
      })
      } else {
        res.send(err);
      }
    });
  })
  } else {
    req.flash("error", "Παρακαλώ συνδεθείτε/Εγγραφείτε.")
    res.redirect("/");
  }
});

app.post("/fuel", function(req, res) {
  const newFuel = new Fuel({
    type: req.body.type,
    date: req.body.date,
    from: req.body.from,
    comment: req.body.comment,
    amount: req.body.amount
  });

  newFuel.save(function(err) {
    if (!err) {
      res.redirect("fuel");
    } else {
      res.send(err);
    }
  })
});

app.post("/deletefuel", function(req, res) {
      Fuel.deleteOne({_id: req.body.id}, function(err) {
        if(!err) {
          res.redirect("fuel");
        } else {
          res.send(err);
        }
      })
    });

//////////////     HTTP Requests for Downloads Route     //////////////

app.get("/downloads", function(req,res) {
  if (req.isAuthenticated()) {
    Filedetail.find(function(err, founddetails) {
      if(founddetails) {
       res.render("downloads", {founddetails:founddetails, errorMessage:req.flash("error"), userid:req.user._id});
      } else {
        res.send(err);
     }
   });
  } else {
    req.flash("error", "Παρακαλώ συνδεθείτε/Εγγραφείτε.")
    res.redirect("/");
  }
});

app.post("/uploadOne", function(req, res) {
  const file = req.file;
  if (!file) {
    req.flash("error", "Λάθος τύπος αρχείου. Παρακαλώ ανεβάστε αρχείο τύπου (.rar).")
    res.redirect("/downloads");
  } else {
    const newPath = new Filedetail({
      name: file.originalname,
      path: file.path
    });
    newPath.save(function(err) {
      if (!err) {
        res.redirect('/downloads');
      } else {
        res.send(err);
      }
    });
  }
});

app.post("/deleteFile", function(req, res) {
  const path = req.body.path;
  Filedetail.find({path:path}, function(err, founddetails) {
    const file = __dirname + '/' + founddetails[0].path;
    fs.unlink(file, function(err) {
      if (err) {
        console.log(err);
      } else {
        Filedetail.findOneAndDelete({path:path}, function(err, founddetails) {
          if (!err) {
            res.redirect("/downloads");
          } else {
            res.send(err);
          }
        });
      }
    });
  });
});


//////////////////    SORTING REQUESTS    ///////////////////////////



//////////////////    Server listens to port 3000     ///////////////////////////

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
