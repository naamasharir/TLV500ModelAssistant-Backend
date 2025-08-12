# TLV500 Backend 🖥️

שרת Backend עבור TLV500 AI Assistant - API מתקדם לעוזר AI פיננסי.

## 📋 תיאור הפרויקט

שרת Node.js/Express המספק API מתקדם לעוזר AI הפיננסי. הפרויקט כולל אינטגרציה עם Gemini AI, Google Sheets API, מסד נתונים MongoDB, ומערכת אימות מאובטחת.

## ✨ תכונות עיקריות

- 🤖 **AI Engine** - אינטגרציה עם Google Gemini AI
- 📊 **Google Sheets API** - קריאה ועריכה אוטומטית של גיליונות
- 🔐 **מערכת אימות** - Google OAuth 2.0 עם Passport.js
- 📄 **עיבוד קבצים** - תמיכה ב-PDF, Excel, CSV עם Multer
- 💾 **MongoDB** - מסד נתונים לשמירת היסטוריית צ'אט ומשתמשים
- 📝 **מערכת לוגים** - Winston עם rotation יומי
- 🔄 **Session Management** - ניהול סשנים מאובטח
- 🌐 **CORS** - הגדרות אבטחה מתקדמות

## 🛠️ טכנולוגיות

- **Node.js** - סביבת ריצה
- **Express 4.19.2** - framework שרת
- **MongoDB 8.16.4** - מסד נתונים NoSQL
- **Google Generative AI** - Gemini AI integration
- **Passport.js** - מערכת אימות
- **Winston** - מערכת לוגים מתקדמת
- **Multer** - העלאת קבצים
- **XLSX** - עיבוד קבצי Excel

## 🚀 התקנה והפעלה

### דרישות מוקדמות
- Node.js (גרסה 16 או חדשה יותר)
- MongoDB (מותקן מקומית או MongoDB Atlas)
- חשבון Google Cloud עם API keys
- npm או yarn

### 1. שיבוט הפרויקט
```bash
git clone <repository-url>
cd TLV500-Backend
```

### 2. התקנת תלותות
```bash
npm install
```

### 3. הגדרת משתני סביבה
העתק את קובץ `.env.example` ל-`.env`:
```bash
cp .env.example .env
```

ערוך את קובץ `.env` והכנס את המפתחות שלך:
```env
# Google APIs
GOOGLE_API_KEY=your_actual_google_api_key
GOOGLE_CLIENT_ID=your_actual_google_client_id
GOOGLE_CLIENT_SECRET=your_actual_google_client_secret

# MongoDB
MONGODB_URI=mongodb://localhost:27017/tlv500-db
# או עבור MongoDB Atlas:
# MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/tlv500-db

# Session Secret
SESSION_SECRET=your_random_session_secret_key

# Server Settings
PORT=5001
NODE_ENV=development

# Frontend URL (for CORS)
FRONTEND_URL=http://localhost:3000
```

### 4. הפעלת MongoDB
```bash
# עבור התקנה מקומית
mongod

# עבור MongoDB Atlas - לא נדרש
```

### 5. הפעלת השרת
```bash
# פיתוח (עם nodemon)
npm run dev

# פרודקשן
npm start
```

השרת יפעל על: `http://localhost:5001`

## 📁 מבנה הפרויקט

```
├── index.js              # נקודת כניסה ראשית
├── logger.js             # הגדרות Winston logger
├── package.json          # תלותות ופקודות
├── .env.example          # דוגמה למשתני סביבה
├── .gitignore           # קבצים להתעלמות
├── web.config           # הגדרות IIS (עבור Azure)
├── models/              # מודלים של MongoDB
│   ├── User.js          # מודל משתמש
│   ├── ChatHistory.js   # היסטוריית צ'אט
│   ├── ActionHistory.js # היסטוריית פעולות
│   └── ChangePlan.js    # תוכניות שינוי
├── uploads/             # קבצים זמניים שהועלו
└── logs/                # קבצי לוג
    └── *.log           # לוגים יומיים
```

## 🔗 API Endpoints

### בריאות השרת
- `GET /api/health` - בדיקת תקינות השרת

### אימות
- `GET /auth/google` - התחלת תהליך OAuth
- `GET /auth/google/callback` - callback של Google OAuth
- `POST /auth/logout` - יציאה מהמערכת

### ניהול קבצים
- `POST /api/upload_file` - העלאת קבצים (PDF, Excel, CSV)

### Google Sheets
- `POST /api/set_access_token` - הגדרת טוקן גישה
- `GET /api/list_sheets` - רשימת גיליונות זמינים
- `POST /api/select_sheet` - בחירת גיליון לעבודה
- `GET /api/get_sheet_data` - קריאת נתוני גיליון
- `POST /api/update_sheet` - עדכון נתונים בגיליון

### צ'אט עם AI
- `POST /api/chat` - שיחה עם AI
- `POST /api/auto_update_sheet` - עדכון אוטומטי של גיליון
- `GET /api/chat_history` - קבלת היסטוריית צ'אט

### ניהול משתמשים
- `GET /api/user/profile` - פרופיל משתמש
- `PUT /api/user/settings` - עדכון הגדרות משתמש

## 💾 מודלים של מסד הנתונים

### User
```javascript
{
  googleId: String,
  email: String,
  name: String,
  picture: String,
  accessToken: String,
  refreshToken: String,
  createdAt: Date,
  lastLogin: Date
}
```

### ChatHistory
```javascript
{
  userId: ObjectId,
  sessionId: String,
  messages: [{
    role: String, // 'user' or 'assistant'
    content: String,
    timestamp: Date
  }],
  createdAt: Date
}
```

### ActionHistory
```javascript
{
  userId: ObjectId,
  action: String,
  details: Object,
  timestamp: Date,
  success: Boolean
}
```

## 🔧 הגדרות מתקדמות

### לוגים
הפרויקט משתמש ב-Winston עם:
- **Console logging** - לפיתוח
- **File rotation** - לוגים יומיים
- **Error tracking** - לוגי שגיאות נפרדים

### Session Management
- **MongoDB Session Store** - שמירת סשנים במסד הנתונים
- **Secure cookies** - עוגיות מאובטחות
- **Auto expiration** - פקיעת סשנים אוטומטית

### CORS
מוגדר לאפשר בקשות מ:
- `http://localhost:3000` (פיתוח)
- כתובות פרודקשן (לפי הגדרה)

## 🚀 פרסום לפרודקשן

### דרישות
- שרת עם Node.js
- MongoDB זמין
- משתני סביבה מוגדרים
- Domain עם HTTPS

### שלבי פרסום
```bash
# 1. בניית הפרויקט
npm run build

# 2. הגדרת משתני סביבה לפרודקשן
NODE_ENV=production
PORT=443
MONGODB_URI=mongodb+srv://...
FRONTEND_URL=https://yourdomain.com

# 3. הפעלת השרת
npm start
```

## 🐛 פתרון בעיות נפוצות

### 1. שגיאות חיבור למסד נתונים
```
MongooseError: Could not connect to MongoDB
```
**פתרון**: ודא ש-MongoDB פועל ו-MONGODB_URI נכון

### 2. שגיאות Google API
```
Error: invalid_client
```
**פתרון**: בדוק את המפתחות ב-Google Cloud Console

### 3. שגיאות CORS
```
CORS policy: No 'Access-Control-Allow-Origin' header
```
**פתרון**: ודא שכתובת הפרונטאנד מוגדרת ב-FRONTEND_URL

### 4. שגיאות העלאת קבצים
```
Error: LIMIT_FILE_SIZE
```
**פתרון**: הקובץ גדול מדי (מקסימום 10MB)

## 📊 ניטור ולוגים

### מיקום לוגים
- **Console**: פלט ישיר לטרמינל
- **Files**: `logs/application-YYYY-MM-DD.log`
- **Errors**: `logs/error-YYYY-MM-DD.log`

### רמות לוג
- `error`: שגיאות חמורות
- `warn`: אזהרות
- `info`: מידע כללי
- `debug`: מידע מפורט לפיתוח

## 🔒 אבטחה

- **Environment Variables** - כל המפתחות ב-env files
- **HTTPS Only** - בפרודקשן
- **CORS Restricted** - מוגבל לדומיינים מאושרים
- **Session Security** - עוגיות מאובטחות
- **Input Validation** - ולידציה של כל הקלטות

## 🧪 בדיקות

```bash
# הרצת בדיקות יחידה
npm test

# בדיקות עם כיסוי
npm run test:coverage

# בדיקות אינטגרציה
npm run test:integration
```

## 🤝 תרומה לפרויקט

1. עשה Fork לפרויקט
2. צור branch חדש (`git checkout -b feature/amazing-feature`)
3. עשה commit לשינויים (`git commit -m 'Add amazing feature'`)
4. דחף ל-branch (`git push origin feature/amazing-feature`)
5. פתח Pull Request

## 📝 רישיון

פרויקט זה מיועד לשימוש פנימי בלבד.

---

**TLV500 Backend** - המנוע החכם מאחורי העוזר הפיננסי! 🚀