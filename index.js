import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import axios from "axios";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;

const saltRounds = 10;
env.config();
//Database
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT
  });
  db.connect();

  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(express.static("public"));

  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
      cookie : {
        maxAge : 1000 * 60 * 60
      }
    })
  );

  //passort should come after session
  app.use(passport.initialize());
  app.use(passport.session());

  //To display home page
  app.get("/", async(req, res) => {
    res.render("home.ejs")
  });
  
  //Home option to return back to home  page
  app.get("/home", async (req, res) => {
    res.redirect("/");
  })

  //To display user registration form
  app.get("/register", (req, res) => {
    res.render("register.ejs");
  })
  
  //To login
  app.get("/login", (req, res) => {
    res.render("login.ejs")
  })

  app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });


  //Directly call and display book details if there is a session
  app.get("/books",async (req, res) => {
    if(req.isAuthenticated()){
      const final_details = await display_books(req.user.user_id);
      res.render("books.ejs",{
        books: final_details,
        username: req.user.username
      });
    }
    else{
      res.render("books.ejs",{
        error_message: "Please login to see the book details"
      });
    }
    
  })

  //Login validation and display books
  app.post("/uservalidate", passport.authenticate("local",{
    successRedirect: "/books",
    failureRedirect: "/login"
  }));

  //inserting new user details to database
  app.post("/newuser", async (req, res) => {
    const username = req.body.username
    const password = req.body.password
    try {
      //password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if(err){
          console.log("Something went wrong on Hash funtion")
        }
        else{
          try {
            const result = await db.query("INSERT INTO users (username, password) VALUES ($1, $2) returning *", [username, hash]);
            const user = result.rows[0];
            req.login(user, (err) => {
              console.log(err);
              res.redirect("/books")
            })
          } catch (error) {
            console.log(error);
            res.render("register.ejs", {
              error_message : "Username already exist!!!!"
          });
          }
          
        }
      })
      
    } catch (error) {
      console.log(error)
      res.render("books.ejs", {
        error_message : "Something went wrong. Please try again!!"
     });
    }
  })

  let book_cover = async (book_details)  => {
    let final_details = [];
    for (const book of book_details) {
        const result = await axios.get(`https://covers.openlibrary.org/b/isbn/${book.bookid}-L.jpg`);
        const img_url = result.config.url;
        book.img_url = img_url;
        final_details.push(book);
    };
    return final_details;
  }

  let display_books = async (user_id) => {
    const result = await db.query("select * from book join review on book.bookid = review.bookid and book.user_id = $1 order by book.bookid",[user_id]);
    const book_details = result.rows;
    const final_details = await book_cover(book_details);
    return final_details;
  }

  app.get("/new", (req, res) => {
    if(user_id > 0){
      res.render("index.ejs")
    } else{
      res.render("books.ejs", {
        error_message : "Please login to add book details"
      })
    } 
  })

  app.post("/add", async(req,res) => {
    const bookid = req.body.bookid;
    const title = req.body.title;
    const description = req.body.description;
    const review = req.body.review;
    const rating = req.body.rating;
    try {
        await db.query("INSERT INTO book (user_id, bookid, title, description) VALUES ($1, $2, $3, $4)", 
        [user_id, bookid, title, description]);
        await db.query("INSERT INTO review (user_id, bookid, review, rating) VALUES ($1, $2, $3, $4)",
        [user_id, bookid, review, rating]);
        const final_details = await display_books(user_id);
        res.render("books.ejs", {
            books : final_details,
            username : userDisplayName
        });
        
    } catch (error) {
        console.log("Error in updating database"+error)
        res.render("index.ejs", {
            error_message : "Something went wrong!! Please try again!!"
        })
    }
    
  })

  //This stategy is verifying to authenticate user login
  passport.use(new Strategy(async function verify(username, password, cb){
    try {
      const data = await db.query("SELECT * FROM users where username = $1", [username]);
      let user = data.rows[0];
      let hashed_password = data.rows[0].password;
      //authenticating user entered password vs encrypted db password
      bcrypt.compare(password, hashed_password, async (err, result) => {
        if(err){
          return cb(err)
        }
        else {
          if(result){
            return cb(null, user)
          }
          else{
            return cb(null, false)
          }
        }
      })
    } catch (error) {
      return cb("Invalid username")
    }
  }))

  passport.serializeUser((user, cb) => {
    cb(null, user);
  })

  passport.deserializeUser((user, cb) => {
    cb(null, user);
  })

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });