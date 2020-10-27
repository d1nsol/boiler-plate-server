const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const moment = require("moment");

const userSchema = mongoose.Schema({
    name: {
        type:String,
        maxlength:50
    },
    email: {
        type:String,
        trim:true,
        unique: 1 
    },
    password: {
        type: String,
        minglength: 5
    },
    lastname: {
        type:String,
        maxlength: 50
    },
    role : {
        type:Number,
        default: 0 
    },
    image: String,
    token : {
        type: String,
    },
    tokenExp :{
        type: Number
    }
})

//save 전 수행됨
userSchema.pre('save', function(next) {
    const user = this;
    if(user.isModified('password')) {
        // 비밀번호를 암호화 시킨다.
        // Salt 를 이용해서 비밀번호를 암호화 해야함
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err) {
                return next(err);
            }
            bcrypt.hash(user.password, salt, function(err, hash) {
                if(err) {
                    return next(err);
                }
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
});

userSchema.methods.comparePassword = function(plainPassword, callBackFunction) {
    
    // plainPassword 와 암호화된 비밀번호 비교
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err) return callBackFunction(err);
        callBackFunction(null, isMatch);
    });
};

userSchema.methods.generateToken = function(callBackFunction) {

    const user = this;
    
    // jsonwebtoken 을 이용해서 token 을 생성하기
    const token = jwt.sign(user._id.toHexString(), 'secretToken');
    const oneHour = moment().add(1, 'hour').valueOf();
    user.tokenExp = oneHour;
    user.token = token;
    user.save(function(err, user) {
        if(err) return callBackFunction(err);
        callBackFunction(null, user);
    });
    
}

userSchema.statics.findByToken = function(token, callBackFunction) {
    const user = this;

    // 토큰을 decode 한다.
    jwt.verify(token, 'secretToken', function(err, decoded) {
        // 유저 아이디를 이용해서 유저를 찾은 다음에
        // 클라이언트에서 가져온 token 과 DB 에 보관된 토큰이 일치하는지 확인

        user.findOne({"_id": decoded, "token": token}, function(err, user) {
            if(err) {
                return callBackFunction(err);
            }
            callBackFunction(null, user);
        });
    });
}

const User = mongoose.model('User', userSchema);

module.exports = { User }