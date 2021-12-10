const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5,
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function (next) {
    const user = this;

    if(user.isModified('password')){
        // 비밀번호 암호화
        bcrypt.genSalt(saltRounds, function (err, salt) {
            if(err) return next(err);

            bcrypt.hash(user.password, salt, function (err, hash) {
                if(err) return next(err);

                user.password = hash;
                next();
            })
        })
    } else {
        next();
    }
})

userSchema.methods.comparePassword = function (plainPassword, cb) {
    // plainPassword: 1234567 (암호화된 비밀번호) $2b$10$OSZZoqwViZG/ZhU6sO8xAOO4Mw0.0ULCc11.GjV/NO/MK4PEJBGGK 비교
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err) return cb(err);

        cb(null, isMatch);
    })
}

userSchema.methods.generateToken = function(cb) {
    const user = this;

    //jsonwebtoken 이용해서 토큰 생성
    const token = jwt.sign(user._id.toHexString(), 'secretToken');

    user.token = token;
    user.save(function (err, userInfo) {
        if(err) return cb(err);
        cb(null, userInfo);
    });
}

userSchema.statics.findByToken = function(token, cb) {
    const user = this;

    //토큰 복호화
    jwt.verify(token, 'secretToken', function(err, decoded){
        // 유저 아이디를 이용해서 유저 찾은 뒤
        // 클라이언트에서 가져온 token과 DB에 보관된 token의 일치 여부 확인
        user.findOne({"_id":decoded, "token": token}, function(err, user){
            if(err) return cb(err);
            cb(null, user);
        })
    })
}

const User = mongoose.model('User', userSchema);

module.exports = {User}