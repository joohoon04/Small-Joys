"use strict";

const helmet = require('helmet');
const express = require("express");
const app = express();
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");  
const MongoStore = require("connect-mongo"); 

// 1. 미들웨어 설정
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// app.js
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"], 
            scriptSrc: ["'self'", "'unsafe-inline'"], 
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "data:"], 
            connectSrc: ["'self'", "http://localhost:3000"] 
        },
    },
}));
app.use(express.static('public'));

// 2. 뷰 엔진 설정
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// 3. MongoDB 연결
const mongoUrl = process.env.MONGO_URL;
mongoose.connect(mongoUrl), {
    useNewUrlParser: true,
    useUnifiedTopology: true
}

.then(() => console.log("MongoDB 연결 성공"))
.catch(err => console.error("MongoDB 연결 실패:", err));


app.use(express.static('public'));
// 4. Express 세션 설정
app.use(session({
    secret: "mySecretKey123!",
    resave: false,
    saveUninitialized: true,
    store: new MongoStore({ 
        mongoUrl: mongoUrl,
        collectionName: 'sessions' // 세션 컬렉션 이름 지정 (선택 사항)
    })
}));

// 5. 라우터 연결
const index = require("./routes/index"); 
app.use("/", index); 

// 6. 서버 실행
// Render에서는 환경 변수 PORT를 사용하고, 로컬에서는 3000번을 사용합니다.
const PORT = process.env.PORT || 3000; 
app.listen(PORT, function () {
    console.log(`${PORT}번 포트 실행 중입니다.`);
});