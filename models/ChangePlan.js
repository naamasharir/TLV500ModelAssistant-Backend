const mongoose = require('mongoose');

const changePlanSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  sessionId: {
    type: String,
    required: true,
    index: true
  },
  planId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userRequest: {
    type: String,
    required: true
  },
  isSignificantChange: {
    type: Boolean,
    required: true
  },
  analysisResult: {
    // התוצאה המלאה מג'מיני
    fullAnalysis: String, // The complete text response from Gemini
    complexity: String,
    executionPlan: String, // The detailed plan in natural language
    potentialIssues: String,
    clarificationQuestions: [String],
    languageNote: String
  },
  clarificationAnswers: {
    type: [String],
    default: []
  },
  status: {
    type: String,
    enum: ['PENDING_CLARIFICATION', 'READY_FOR_EXECUTION', 'EXECUTED', 'CANCELLED'],
    default: 'PENDING_CLARIFICATION'
  },
  finalActions: {
    type: mongoose.Schema.Types.Mixed,
    // הפעולות הסופיות לביצוע אחרי ההבהרות
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// עדכון updatedAt אוטומטי
changePlanSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// מתודות סטטיות
changePlanSchema.statics.createNewPlan = async function(userId, sessionId, userRequest, analysisResult) {
  const planId = `plan_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  
  const plan = new this({
    userId,
    sessionId,
    planId,
    userRequest,
    isSignificantChange: true,
    analysisResult,
    status: 'PENDING_CLARIFICATION'
  });
  
  return await plan.save();
};

changePlanSchema.statics.findByPlanId = async function(planId) {
  return await this.findOne({ planId });
};

changePlanSchema.statics.addClarificationAnswers = async function(planId, answers) {
  const plan = await this.findOne({ planId });
  if (!plan) return null;
  
  plan.clarificationAnswers = answers;
  plan.status = 'READY_FOR_EXECUTION';
  return await plan.save();
};

module.exports = mongoose.model('ChangePlan', changePlanSchema); 