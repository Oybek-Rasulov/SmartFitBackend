import express from 'express';
import env from 'dotenv';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcrypt';
import admin from 'firebase-admin';
import { encrypt, decrypt } from './utils/cryptoUtils.js';
// import { pool } from '../db/db.js'; // or wherever your pool is initialized
import jwt from 'jsonwebtoken';
import fs from 'fs';
const serviceAccount = JSON.parse(fs.readFileSync('./serviceAccountKey.json', 'utf8'));

env.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // For remote connections (adjust accordingly)
})

db.connect();

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// app.post('/api/auth/firebase-login', async (req, res) => {
//   const { token } = req.body;

//   try {
//     const decodedToken = await admin.auth().verifyIdToken(token);
//     console.log('Decoded Firebase User:', decodedToken);

//     // You can now find/create user in your DB using decodedToken.uid / email
//     res.status(200).json({ success: true, uid: decodedToken.uid });
//   } catch (error) {
//     console.error('Token verification failed:', error);
//     res.status(401).json({ error: 'Invalid token' });
//   }
// });

// Routes
const authenticateAdmin = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach the decoded admin data to the request object
    req.admin = decoded;

    // Check if the user has an admin role (optional)
    if (req.admin.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied. Not an admin.' });
    }

    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(400).json({ message: 'Invalid token.' });
  }
};

app.get('/news', async (req, res) => {
    const result = await db.query('SELECT * FROM news');
    const data = result.rows;
    if(data.length > 0) res.status(201).json(data);
});

app.post('/register', async (req, res) => {
    try {
        const {phone, password} = req.body;

        const result = await db.query("SELECT phone FROM users WHERE phone = $1", [phone]);
        const check = result.rows

        const salt = 10;
        const hash = await bcrypt.hash(password, salt);

        if(check.length > 0) {
            res.status(401).json({message: "available"})
        }else {
            await db.query("INSERT INTO users (phone, password, name, instagram, telegram, bio) VALUES($1, $2, $3, $4, $5, $6)", [phone, hash, "Unknown User", "https...", "https...", "Ozingiz haqingizda qisqacha..."]);
            res.status(201).json({message: "success"})
        }

    }catch(err) {
        console.log(err)
    }
})

app.post('/login', async (req, res) => {
    try {
        const {phone, password} = req.body;

        const result = await db.query("SELECT phone, password FROM users WHERE phone = $1", [phone]);
        const check = result.rows

        if(check.length === 0) return res.status(401).json({message: "not available"})

        const isMatch = await bcrypt.compare(password, check[0].password);

        if(isMatch) {
            res.status(201).json({message: phone});
        }else {
            res.status(401).json({message: "failed"})
        }   
    }catch(err) {
        console.log(err)
    }
})

app.post("/data", async (req, res) => {
    const {user} = req.body;

    res.status(201).json({});
})

// Trainers
app.get('/trainers', async (req, res) => {
    try {
        const result = await db.query("SELECT * FROM trainers");
        const trainers = result.rows
        res.status(201).json(trainers)
    }catch(err) {
        console.log(err)
    }
})

app.post('/trainer', async (req, res) => {
    try {
        const {trainerid} = req.body;
        const result = await db.query("SELECT * FROM trainers WHERE trainerid = $1", [trainerid]);
        const trainer = result.rows;
        res.status(201).json(trainer);
    }catch(err) {
        console.log(err)
    }
});

app.post('/tuser', async (req, res) => {
    try {
        const {user} = req.body;

        const result = await db.query("SELECT * FROM trainers WHERE phone = $1", [user])
        const userData = result.rows;
        res.status(201).json(userData);
    }catch(err) {
        console.log(err)
    }

})

app.post('/user', async (req, res) => {
    try {
        const {user} = req.body;
        const result = await db.query('SELECT * FROM users WHERE phone = $1', [user])
        const userData = result.rows;
        res.status(201).json(userData);
    }catch(err) {
        console.log(err)
    }

})

app.post('/edituser', async (req, res) => {
    try {
        const {name, bio, instagram, telegram, user} = req.body;
        await db.query("UPDATE users SET name = $1, bio = $2, instagram = $3, telegram = $4 WHERE phone = $5", [name, bio, instagram, telegram, user])

    }catch(err) {
        console.log(err)
    }
});

app.post('/editTrainer', async (req, res) => {
    try {
        const {name, bio, instagram, telegram, experience, students, age, user} = req.body;
        await db.query("UPDATE trainers SET name = $1, bio = $2, instagram = $3, telegram = $4, experience = $5, students = $6, age = $7 WHERE phone = $8", [name, bio, instagram, telegram, experience, students, age, user])

    }catch(err) {
        console.log(err)
    }
});

// Trainer part
app.post('/tlogin', async (req, res) => {
    try {
        const {phone, password} = req.body;

        const result = await db.query('SELECT * FROM trainers WHERE phone = $1', [phone])
        const trainerData = result.rows[0]

        if(!trainerData) return res.status(404).json({message: 'not available'}) 

        const isMatch = await bcrypt.compare(password, trainerData.password)

        if(isMatch) {
            res.status(201).json({message: phone });
        }else{
            res.status(401).json({message: "incorrect"})
        }
    }catch(err) {
        console.log(err)
    }
})

// Sign up and Sign in
app.post('/api/auth/firebase-login', async (req, res) => {
    const { token } = req.body;
  
    try {
      const decoded = await admin.auth().verifyIdToken(token);
      const {
        name,
        email,
        picture: photo,
        user_id,
        firebase: { sign_in_provider: provider },
      } = decoded;
      
      const uid = user_id; // ✅ assign manually
    
      const fallbackEmail = email || `${uid}@firebaseuser.local`;
      const fallbackName = name || 'Unknown User'; // ✅ added

      const encryptedEmail = fallbackEmail ? encrypt(fallbackEmail) : null;
      const encryptedName = fallbackName ? encrypt(fallbackName) : null;
  
      const result = await db.query(
        `
        INSERT INTO users (userid, name, phone, image, provider)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (userid) DO UPDATE
        SET name = EXCLUDED.name,
            phone = EXCLUDED.phone,
            image = EXCLUDED.image,
            provider = EXCLUDED.provider
        RETURNING *;
        `,
        [uid, encryptedName, encryptedEmail, photo, provider]
      );
  
      res.status(200).json({
        message: 'User logged in and saved',
        user: result.rows[0],
      });
    } catch (error) {
      console.error('❌ Firebase token verification failed:', error);
      res.status(401).json({ error: 'Invalid token' });
    }
  });


app.get('/api/users', async (req, res) => {
    try {
      const result = await db.query('SELECT * FROM users');
  
      const decryptedUsers = result.rows.map(user => ({
        ...user,
        name: user.name ? decrypt(user.name) : null,
        phone: user.phone ? decrypt(user.phone) : null,
      }));
  
      res.json(decryptedUsers);
    } catch (error) {
      console.error('Error fetching users:', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });


//   Community chat
  app.get('/api/chat-groups', async (req, res) => {
    try {
      const result = await db.query('SELECT * FROM chat_groups ORDER BY name');
      res.json(result.rows);
    } catch (err) {
      console.error('Error fetching groups:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  
  app.get('/api/chat-groups/:id/messages', async (req, res) => {
    const { id } = req.params;
  
    try {
      const result = await db.query(
        `SELECT gm.*, u.name, u.image
         FROM group_messages gm
         JOIN users u ON u.userid = gm.user_id
         WHERE group_id = $1
         ORDER BY created_at ASC`,
        [id]
      );

      const decryptedUsers = result.rows.map(user => ({
        ...user,
        name: user.name ? decrypt(user.name) : null,
        message: user.message ? decrypt(user.message) : null,
      }));

      res.json(decryptedUsers);
    } catch (err) {
      console.error('Error fetching messages:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  app.post('/api/chat-groups/:id/messages', async (req, res) => {
    const { id } = req.params;
    const { user_id, message } = req.body;
  
    try {

      const encryptedMessage = message ? encrypt(message) : null;
      await db.query(
        `INSERT INTO group_messages (group_id, user_id, message)
         VALUES ($1, $2, $3)`,
        [id, user_id, encryptedMessage]
      );
  
      res.status(201).json({ success: true, message: 'Message sent' });
    } catch (err) {
      console.error('Error posting message:', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // API endpoint to get all trainers
app.get('/api/trainers', async (req, res) => {
  try {
    // Query to get all trainers from the PostgreSQL database
    const result = await db.query('SELECT * FROM trainers');
    
    // Sending the trainers data as JSON response
    res.json(result.rows); // `result.rows` contains the array of trainers
  } catch (error) {
    console.error('Error fetching trainers:', error);
    res.status(500).json({ message: 'Error fetching trainers' });
  }
});
  
// Admin login route
// Protect admin routes with authenticateAdmin middleware
app.get('/api/admin', authenticateAdmin, (req, res) => {
  // If the user is authenticated and an admin, allow access
  res.json({ message: 'Welcome to the admin dashboard!' });
});


app.post('/api/admin-login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Check if the admin exists
    const result = await db.query('SELECT * FROM adminLogin WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const admin = result.rows[0];

    // 2. Compare password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, admin.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // 3. Generate JWT token if authentication is successful
    const token = jwt.sign(
      { id: admin.id, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION || '1h' }
    );

    // 4. Send the JWT token back in the response
    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get messages between user and trainer
app.get("/api/messages/:trainerId", async (req, res) => {
  const { trainerId } = req.params;

  try {
    const result = await db.query(
      "SELECT * FROM messages WHERE trainer_id = $1 ORDER BY created_at ASC",
      [trainerId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ message: "Failed to fetch messages" });
  }
});

// Send a new message
app.post('/api/messages', async (req, res) => {
  const { trainerId, message, userId } = req.body;
  console.log(trainerId, message, userId)

  if (!trainerId || !message || !userId) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const result = await db.query(
      "INSERT INTO messages (trainer_id, message, sender, user_id) VALUES ($1, $2, 'user', $3) RETURNING *",
      [trainerId, message, userId] // Store trainerId, message, and userId
    );
    res.json(result.rows[0]); // Send the newly created message
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

app.post('/api/ratings', async (req, res) => {
  const { trainerId, userId, rating } = req.body;

  if (!trainerId || !userId || !rating) {
    return res.status(400).json({ message: 'Missing data' });
  }

  try {
    // Check if the user has already rated this trainer
    const existingRating = await db.query(
      'SELECT * FROM ratings WHERE trainer_id = $1 AND user_id = $2',
      [trainerId, userId]
    );

    if (existingRating.rows.length > 0) {
      // Update the existing rating
      await db.query(
        'UPDATE ratings SET rating = $1 WHERE trainer_id = $2 AND user_id = $3',
        [rating, trainerId, userId]
      );
      return res.json({ message: 'Rating updated' });
    } else {
      // Insert a new rating
      await db.query(
        'INSERT INTO ratings (trainer_id, user_id, rating) VALUES ($1, $2, $3)',
        [trainerId, userId, rating]
      );
      return res.json({ message: 'Rating submitted' });
    }
  } catch (error) {
    console.error('Error submitting rating:', error);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.get('/ratings/:trainerId', async (req, res) => {
  const { trainerId } = req.params;

  try {
    const result = await db.query(
      'SELECT AVG(rating) as avg_rating FROM ratings WHERE trainer_id = $1',
      [trainerId]
    );
    const avgRating = result.rows[0].avg_rating || 0;
    res.json({ avgRating });
  } catch (error) {
    console.error('Error fetching ratings:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/submitRating', async (req, res) => {
  const { trainerId, userId, rating } = req.body;

  if (!trainerId || !userId || !rating) {
    return res.status(400).json({ error: 'Trainer ID, User ID, and rating are required' });
  }

  try {
    // Insert the rating into the database, ensuring user_id and trainer_id are not null
    const result = await db.query(
      'INSERT INTO ratings (trainer_id, user_id, rating) VALUES ($1, $2, $3) RETURNING *',
      [trainerId, userId, rating]
    );

    // Get the new average rating for the trainer
    const avgRatingResult = await db.query(
      'SELECT AVG(rating) AS avgRating FROM ratings WHERE trainer_id = $1',
      [trainerId]
    );

    // Return the new average rating
    res.json({ newAverageRating: avgRatingResult.rows[0].avgRating });
  } catch (error) {
    console.error('Error submitting rating:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Endpoint to fetch average rating of a trainer
app.get('/api/trainers/ratings', async (req, res) => {
  try {
    // Query to get average rating for each trainer
    const result = await db.query(
      'SELECT trainer_id, AVG(rating) AS avgRating FROM ratings GROUP BY trainer_id'
    );

    // If no data is found
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No ratings found for trainers.' });
    }
    // Send back the average ratings
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching ratings:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Route to handle the trainer form submission
app.post('/tform', async (req, res) => {
  const {
      name,
      phone,
      password,
      age,
      experience,
      studentNumbers,
      gender,
      uzbek,
      russian,
      directions,
  } = req.body;

  try {
      const hashedPassword = await bcrypt.hash(password, 10); 
      // Insert data into the temporaryTrainer table
      const result = await db.query(
          `INSERT INTO temporaryTrainer (name, phone, password, age, experience, studentNumbers, gender, uzbek, russian, directions) 
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
          [
              name,
              phone,
              hashedPassword, // Make sure to hash the password before storing it in a real project
              age,
              experience,
              studentNumbers,
              gender,
              uzbek,
              russian,
              directions,
          ]
      );

      const trainer = result.rows[0];
      res.json({ message: 'success', trainer });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'failed', error: error.message });
  }
});


// // trainer form
app.post('/accessTrainer', async (req, res) => {
  try {
    const { trainerId } = req.body; // Get the trainerId from the request body

    // Fetch the trainer data from the temporarytrainers table using the trainerId
    const trainerResult = await db.query('SELECT * FROM temporarytrainer WHERE id = $1', [trainerId]);
    
    if (trainerResult.rows.length === 0) {
      return res.status(404).json({ message: 'Trainer not found' });
    }
    
    const trainer = trainerResult.rows[0];

    // Insert the trainer data into the trainers table
    await db.query(
      `INSERT INTO trainers (name, phone, password, age, experience, students, gender, status, uzb, rus, directions) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        trainer.name,
        trainer.phone,
        trainer.password, // Ideally, hash the password before storing
        trainer.age,
        trainer.experience,
        trainer.students,
        trainer.gender,
        true, // Set status to true (active)
        trainer.uzb,
        trainer.rus,
        trainer.directions
      ]
    );

    // Delete the trainer from the temporarytrainers table
    await db.query('DELETE FROM temporarytrainer WHERE id = $1', [trainerId]);

    res.status(201).json({ message: 'success' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error processing trainer' });
  }
});


app.get('/api/temporaryTrainers', async (req, res) => {
  try {
    // Query the temporary_trainers table to get all trainers
    const result = await db.query('SELECT * FROM temporarytrainer');
    res.status(200).json(result.rows); // Send the data back as JSON
  } catch (err) {
    console.error('Error fetching temporary trainers:', err);
    res.status(500).json({ message: 'Failed to fetch temporary trainers' });
  }
});





app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
})

