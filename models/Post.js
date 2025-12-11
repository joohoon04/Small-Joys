"use strict";

const mongoose = require("mongoose");

const postSchema = new mongoose.Schema({
    // 1. 게시물 제목
    title: {
        type: String,
        required: true
    },
    // 2. 게시물 내용
    content: {
        type: String,
        required: true
    },
    imageUrl: {
        type: String,
        required: false 
    },
    // 3. 작성자 ID 
    authorId: {
        type: String,
        // type: mongoose.Schema.Types.ObjectId,
        // ref: 'User',
        required: true
    },
    // 4. 작성일 (자동 생성)
    createdAt: {
        type: Date,
        default: Date.now
    },
    // 5. 공개 여부 
    isPublic: {
        type: Boolean,
        default: false 
    },
    ChallengeId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Challenge',
        required: false 
    }
});

module.exports = mongoose.model("Post", postSchema);