// seedChallenges.js
const DB_URI = process.env.MONGO_URL;

// 🚨 1. MongoDB 연결 URI: 사용자님이 사용하시는 URI를 그대로 사용합니다. 🚨
const DB_URI = 'mongodb+srv://hun04:as1234@cluster0.eue8kiz.mongodb.net/rlakf';

const { Challenge, initialChallenges } = require('./models/Challenge'); 

async function seedChallenges() {
    console.log('MongoDB 연결 시도 중...');
    try {
        await mongoose.connect(DB_URI);
        console.log('MongoDB 연결 성공!');
        // 기존 챌린지 데이터 삭제
        console.log('기존 챌린지 데이터 전체 삭제 중...');
        const deleteResult = await Challenge.deleteMany({});
        console.log(`✅ [삭제 완료] ${deleteResult.deletedCount}개의 기존 챌린지 문서를 삭제했습니다.`);

        // 챌린지 데이터 삽입
        console.log(`[시딩] ${initialChallenges.length}개의 새로운 챌린지 삽입 시작...`);
        
        // 6개 데이터가 들어있는 initialChallenges를 삽입합니다.
        const result = await Challenge.insertMany(initialChallenges);
        
        console.log(`✅ [시딩 완료] ${result.length}개의 챌린지가 성공적으로 삽입되었습니다.`);

    } catch (error) {
        console.error('❌ MongoDB 연결 또는 시딩 오류:', error);
    } finally {
        await mongoose.connection.close();
        console.log('MongoDB 연결 종료.');
    }
}

seedChallenges(); // 함수 호출 시작