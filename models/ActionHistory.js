const mongoose = require('mongoose');

const actionHistorySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  sessionId: {
    type: String,
    required: true,
    index: true // לחיפוש מהיר
  },
  snapshotBefore: {
    type: mongoose.Schema.Types.Mixed,
    required: true
    // מכיל את המצב של התאים לפני השינוי
  },
  changeRequest: {
    type: mongoose.Schema.Types.Mixed,
    required: true
    // מכיל את הפעולות שבוצעו (actions array)
  },
  actionType: {
    type: String,
    enum: ['AI_ACTION', 'APPROVE_ALL', 'REJECT_ALL'],
    default: 'AI_ACTION',
    required: true
  },
  status: {
    type: String,
    enum: ['EXECUTED', 'UNDONE'], 
    default: 'EXECUTED',
    required: true
  },
  // נתונים נוספים לשחזור השינוי
  spreadsheetId: {
    type: String,
    required: true
  },
  sheetId: {
    type: Number,
    required: true  
  },
  selectedSheetName: {
    type: String,
    required: true
  },
  changedCells: [{
    type: String // ['A1', 'B2', 'C3']
  }]
}, {
  timestamps: true // מוסיף createdAt ו-updatedAt אוטומטי
});

// אינדקסים למהירות
actionHistorySchema.index({ userId: 1, sessionId: 1, status: 1 });
actionHistorySchema.index({ sessionId: 1, createdAt: -1 }); // למיון לפי זמן

// פונקציות עזר
actionHistorySchema.statics.findLastExecuted = function(sessionId) {
  return this.findOne({ 
    sessionId: sessionId, 
    status: 'EXECUTED' 
  }).sort({ createdAt: -1 });
};

actionHistorySchema.statics.findLastUndone = function(sessionId) {
  return this.findOne({ 
    sessionId: sessionId, 
    status: 'UNDONE' 
  }).sort({ createdAt: -1 });
};

actionHistorySchema.statics.clearRedoHistory = function(sessionId) {
  return this.deleteMany({ 
    sessionId: sessionId, 
    status: 'UNDONE' 
  });
};

actionHistorySchema.statics.getStatus = async function(sessionId) {
  const [executed, undone] = await Promise.all([
    this.findOne({ sessionId: sessionId, status: 'EXECUTED' }),
    this.findOne({ sessionId: sessionId, status: 'UNDONE' })
  ]);
  
  return {
    canUndo: !!executed,
    canRedo: !!undone
  };
};

module.exports = mongoose.model('ActionHistory', actionHistorySchema); 