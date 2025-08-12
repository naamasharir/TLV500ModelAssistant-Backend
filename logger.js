// logger.js

const winston = require('winston');
require('winston-daily-rotate-file');

// --- 1. הגדרת ה-Transport לקבצים עם רוטציה יומית ---
const fileRotateTransport = new winston.transports.DailyRotateFile({
  filename: 'logs/app-%DATE%.log', // תבנית שם הקובץ. %DATE% יוחלף בתאריך.
  datePattern: 'YYYY-MM-DD',      // הפורמט של התאריך בשם הקובץ.
  zippedArchive: true,            // האם לדחוס קבצי לוג ישנים (מומלץ).
  maxSize: '20m',                 // גודל מקסימלי לקובץ לפני שיוצרים אחד חדש (למשל, אם יש המון לוגים).
  maxFiles: '14d',                // שמירת קבצים עד 14 יום אחורה. קבצים ישנים יותר יימחקו.
  level: 'info'                   // רמת החומרה המינימלית שתישמר בקובץ.
});

// --- 2. הגדרת ה-Transport לקונסול (כדי שנמשיך לראות לוגים בטרמינל בזמן פיתוח) ---
const consoleTransport = new winston.transports.Console({
  level: 'debug', // הצג את כל רמות החומרה בקונסול.
  format: winston.format.combine(
    winston.format.colorize(), // הוספת צבעים לרמות השונות
    winston.format.simple()    // פורמט פשוט
  )
});

// --- 3. יצירת הלוגר הראשי עם ההגדרות שקבענו ---
const logger = winston.createLogger({
  level: 'info', // רמת חומרה מינימלית כללית ללוגר.
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), // הוספת חותמת זמן
    winston.format.errors({ stack: true }), // אם הלוג הוא שגיאה, הצג את ה-stack trace
    winston.format.splat(),
    winston.format.json() // שמירת הלוג בפורמט JSON (הכי טוב לניתוח)
  ),
  transports: [
    fileRotateTransport, // שליחת הלוגים לקובץ
    consoleTransport     // וגם לקונסול
  ],
  exitOnError: false // אל תגרום לאפליקציה לקרוס אם יש בעיה בכתיבת הלוג.
});

// אם אנחנו לא בסביבת פרודקשן, נרצה שהכל יודפס לקונסול
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

module.exports = logger;

// פונקציה מיוחדת ללוגים מפורטים (פרומפטים ותגובות)
logger.logDetailed = function(type, direction, content, metadata = {}) {
  const logData = {
    type: type.toUpperCase(),
    direction: direction.toUpperCase(),
    contentLength: content.length,
    content: content,
    ...metadata
  };
  
  this.info(`📝 ${type.toUpperCase()} ${direction.toUpperCase()}`, logData);
  
  // הדפסה קצרה לקונסול
  console.log(`📝 ${type.toUpperCase()} ${direction.toUpperCase()} - Length: ${content.length} chars - Saved to logs`);
  if (metadata.model) console.log(`   Model: ${metadata.model}`);
  if (metadata.purpose) console.log(`   Purpose: ${metadata.purpose}`);
};
