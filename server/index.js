const express = require("express");
const app = express();

const config = require("./config/key");

const { User } = require("./models/User");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

const { auth } = require("./middleware/auth");

// application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// application/json
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require("mongoose");

mongoose
  .connect(config.mongoURI)
  .then(() => console.log("MongoDB Connected..."))
  .catch((err) => console.log(err));

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.post("/api/users/register", (req, res) => {
  // 회원 가입시 필요한 정보를 클라이언트에서 가져오면 서버에서 데이터베이스에 저장
  const user = new User(req.body);

  user.save((err, user) => {
    if (err) {
      return res.json({ success: false, err });
    }
    return res.status(200).json({
      success: true,
    });
  });
});

app.post("/api/users/login", (req, res) => {
  // 요청된 이메일을 데이터베이스에 있는지 확인
  User.findOne({ email: req.body.email }, (err, user) => {
    if (!user) {
      return res.json({
        loginSuccess: false,
        message: "이메일에 해당하는 유저가 없습니다.",
      });
    }
    // 요청된 이메일이 데이터베이스에 있다면, 비밀번호가 맞는지 확인
    user.comparePassword(req.body.password, (err, isMatch) => {
      if (!isMatch)
        return res.json({
          loginSuccess: false,
          message: "비밀번호가 틀렸습니다.",
        });

      // 비밀번호까지 맞다면 토큰 생성
      user.generateToken((err, user) => {
        if (err) return res.status(400).send(err);

        // 토큰을 쿠키에 저장
        res
          .cookie("x_auth", user.token)
          .status(200)
          .json({ loginSuccess: true, userId: user._id });
      });
    });
  });
});

app.get("/api/users/auth", auth, (req, res) => {
  // 여기까지 미들웨어를 통과해서 왔기 때문에 Authentication이 true라는 뜻
  res.status(200).json({
    _id: req.user._id,
    isAdmin: req.user.role === 0,
    isAuth: true,
    email: req.user.email,
    name: req.user.name,
    lastname: req.user.lastname,
    role: req.user.role,
    image: req.user.image,
  });
});

app.get("/api/users/logout", auth, (req, res) => {
  User.findOneAndUpdate({ _id: req.user._id }, { token: "" }, (err, user) => {
    if (err) return res.json({ success: false, err });
    return res.status(200).send({ success: true });
  });
});

app.get("/api/hello", (req, res) => {
  res.send("안녕하세요");
});

const port = 5000;

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
