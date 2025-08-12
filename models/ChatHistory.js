const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  role: { 
    type: String, 
    enum: ['user', 'assistant'], 
    required: true 
  },
  content: { 
    type: String, 
    required: true 
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  },
  metadata: {
    isAgentMode: {
      type: Boolean,
      default: false
    },
    spreadsheetId: {
      type: String,
      default: null
    },
    selectedSheetName: {
      type: String,
      default: null
    },
    hasAttachments: {
      type: Boolean,
      default: false
    },
    attachmentTypes: [{
      type: String,
      enum: ['pdf', 'excel', 'image']
    }],
    processingTime: {
      type: Number, // in milliseconds
      default: null
    }
  }
}, {
  timestamps: true
});

const chatHistorySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  sessionId: {
    type: String,
    required: true
  },
  title: {
    type: String,
    default: 'New Conversation'
  },
  messages: [messageSchema],
  isActive: {
    type: Boolean,
    default: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  summary: {
    type: String,
    default: null
  },
  totalMessages: {
    type: Number,
    default: 0
  },
  lastActivity: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for better performance
chatHistorySchema.index({ userId: 1, sessionId: 1 }, { unique: true }); // Unique combination of user + session
chatHistorySchema.index({ userId: 1, lastActivity: -1 });
chatHistorySchema.index({ userId: 1, isActive: 1, lastActivity: -1 });

// Virtual for message count
chatHistorySchema.virtual('messageCount').get(function() {
  return this.messages.length;
});

// Method to add a message
chatHistorySchema.methods.addMessage = function(role, content, metadata = {}) {
  this.messages.push({
    role,
    content,
    metadata
  });
  
  this.totalMessages = this.messages.length;
  this.lastActivity = new Date();
  
  // Auto-generate title from first user message if still default
  if (this.title === 'New Conversation' && role === 'user' && this.messages.length <= 2) {
    this.title = content.substring(0, 50) + (content.length > 50 ? '...' : '');
  }
  
  return this.save();
};

// Method to get recent messages (last N messages)
chatHistorySchema.methods.getRecentMessages = function(limit = 10) {
  return this.messages.slice(-limit);
};

// Method to get conversation summary
chatHistorySchema.methods.generateSummary = function() {
  if (this.messages.length === 0) return 'Empty conversation';
  
  const userMessages = this.messages.filter(msg => msg.role === 'user');
  if (userMessages.length === 0) return 'No user messages';
  
  // Simple summary from first few user messages
  const firstMessages = userMessages.slice(0, 3).map(msg => msg.content);
  return firstMessages.join(' | ').substring(0, 200);
};

// Static method to find user's chat sessions
chatHistorySchema.statics.findUserSessions = function(userId, limit = 20) {
  return this.find({ userId, isActive: true })
    .sort({ lastActivity: -1 })
    .limit(limit)
    .select('sessionId title lastActivity totalMessages createdAt')
    .lean();
};

// Static method to create new session
chatHistorySchema.statics.createNewSession = function(userId, sessionId, title = 'New Conversation') {
  return this.create({
    userId,
    sessionId,
    title,
    messages: [],
    totalMessages: 0,
    lastActivity: new Date()
  });
};

// Pre-save middleware to update message count and last activity
chatHistorySchema.pre('save', function(next) {
  if (this.isModified('messages')) {
    this.totalMessages = this.messages.length;
    this.lastActivity = new Date();
  }
  next();
});

module.exports = mongoose.model('ChatHistory', chatHistorySchema);