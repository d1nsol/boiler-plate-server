const express = require('express');
const router = express.Router();
const { User } = require("../models/User");

const { auth } = require("../middleware/auth");

//=================================
//             User
//=================================

router.post("/auth", auth, (req, res) => {

    // 여기까지 미들웨어를 통과한건, Authentication 이 true
    // role 0 -> 일반 / 1 -> 관리자
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true,
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image,
    });
});

// 회원등록
router.post("/register", (req, res) => {

    // 회원 가입 할때 필요한 정보들을 client 에서 가져오면
    // 그것들을 데이터 베이스에 넣어준다.

    const user = new User(req.body);
    user.save((err, userInfo) => {
        if(err) {
            return res.json({success: false, err});
        }
        return res.status(200).json({success: true});
    });
});

// 로그인
router.post("/login", (req, res) => {

    // 요청된 이메일을 데이터베이스에서 있는지 찾는다.
    User.findOne({ email: req.body.email }, (err, user) => {
        if(!user) {
            return res.json({
                loginSuccess: false,
                message: "해당 이메일 유저가 없습니다."
            });
        }

        user.comparePassword(req.body.password, (err, isMatch) => {
            if(!isMatch) {
              return res.json({
                loginSuccess: false,
                message: "비밀번호가 틀렸습니다."
              });
            }
      
            // 비밀번호 까지 맞다면 토큰을 생성
            user.generateToken((err, user) => {
              if(err) {
                return res.status(400).send(err);
              }

              console.log('@@@@@ user.tokenExp : ', user.tokenExp);
              console.log('@@@@@ user.token : ', user.token);
      
              // 토큰을 저장한다. 쿠키 or 로컬스토리지
              // to do jsyoo : res.cookie 저장 안되는 이슈 확인하기
              //res.cookie("x_authExp", user.tokenExp);
              //res.cookie("x_auth", user.token);
              res.status(200)
                .json(
                    {
                        loginSuccess: true,
                        userId: user._id,
                        x_authExp: user.tokenExp,
                        x_auth: user.token
                    }
                );
            });
        });
    });
});

router.get("/logout", auth, (req, res) => {
    User.findOneAndUpdate({_id: req.user._id}, {token: "", tokenExp: ""}, (err, user) => {
        if(err) {
          return res.json({success: false, err});
        }
        return res.status(200).send({success: true});
    });
});

module.exports = router;
