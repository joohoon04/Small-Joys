"use strict";

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    id: { // 로그인 ID
        type: String,
        unique: true,
        sparse: true
    },
    password: { // 비밀번호
        type: String,
        required: true
    },
    name: { // 이름
        type: String,
        required: true
    },
    // 이메일
    email: {
        type: String,
        required: false, 
        unique: true, 
        sparse: true
    },
    // 전화번호
    phone: {
        type: String,
        required: false 
    },
    // '랜덤 행복 발견'에 글 노출 동의 여부
    isRandomExposed: { 
        type: Boolean,
        default: true 
    },
    // 사용자가 참여한 챌린지 목록
    joinedChallenges: [{ 
        challengeId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Challenge',
                required: true
            },
            status: { // 참여 상태를 저장하기 위한 필드 추가
                type: String,
                enum: ['참여', '진행중', '성공', '실패'],
                default: '참여' 
            },
            joinedAt: { // 참여 시작일 기록
                type: Date,
                default: Date.now
            }
    }],
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);