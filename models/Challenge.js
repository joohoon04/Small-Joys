const mongoose = require("mongoose");

const challengeSchema = new mongoose.Schema({
    // 챌린지 고유 ID (자동 생성)
    title: { type: String, required: true, trim: true }, // 챌린지 제목
    description: { type: String, required: true }, // 상세 설명
    duration: { type: Number, required: true, default: 7 }, // 목표 일수 (Post 작성 횟수)
    requiredTags: [{ type: String }], // 챌린지 필수 해시태그)
    isActive: { type: Boolean, default: true }, // 현재 활성화 여부
    startDate: { type: Date, default: Date.now },
    endDate: { type: Date }, // 운영자가 설정 (혹은 duration으로 자동 계산)
}, { timestamps: true });

// 챌린지 모델 생성
const Challenge = mongoose.model("Challenge", challengeSchema);

// 초기 챌린지 데이터 배열 정의
const initialChallenges = [
    {
        "title": "오늘 하루 행복 일기",
        "duration": 1, 
        "description": "오늘 느꼈던 단 하나의 소중한 행복을 기록하세요.",
        "requiredTags": ["오늘의행복", "단하나의기록"],
        "isActive": true,
        "startDate": null, 
        "endDate": null
    },
    {
        "title": "3가지 감사 일기",
        "duration": 7,
        "description": "매일 3가지의 감사한 일을 기록해 긍정적인 마음을 키워보세요.",
        "requiredTags": ["매일감사", "고마워요"],
        "isActive": true,
        "startDate": null, 
        "endDate": null
    },
    {
        "title": "소확행 포착",
        "duration": 5,
        "description": "일상 속 작지만 확실한 행복 순간을 사진과 함께 기록합니다.",
        "requiredTags": ["소확행", "순간의행복"],
        "isActive": true,
        "startDate": null,
        "endDate": null
    },
    {
        "title": "나에게 칭찬해",
        "duration": 3,
        "description": "매일 잠들기 전, 오늘 열심히 산 나에게 칭찬 한마디를 남겨요.",
        "requiredTags": ["셀프칭찬", "오늘의성장"],
        "isActive": true,
        "startDate": null,
        "endDate": null
    },
    {
        "title": "친절 실천 기록",
        "duration": 7,
        "description": "타인에게 베푼 작은 친절이나 받은 친절을 기록하고, 그때의 감정을 공유합니다.",
        "requiredTags": ["친절실천", "따뜻한마음"],
        "isActive": true,
        "startDate": null,
        "endDate": null
    }
];

module.exports = { Challenge, initialChallenges };