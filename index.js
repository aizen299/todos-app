const express = require("express");
const { UserModel, TodoModel } = require("./db");
const { auth, JWT_SECRET } = require("./auth");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const { z } = require("zod");

mongoose.connect("mongodb+srv://aditya:aizen299@cluster0.uiyks.mongodb.net/todo-app");

const app = express();
app.use(express.json());

const passwordSchema = z.string()
  .min(8, { message: "Password must be at least 8 characters long" })
  .max(24, { message: "Password must be no longer than 24 characters" })
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(/[\W_]/, "Password must contain at least one special character");


app.post("/signup", async function(req, res) {
    const reqBody = z.object({
        email: z.string().email(),
        name: z.string().min(3).max(100),
        password: passwordSchema 
    });

    const parsedData = reqBody.safeParse(req.body);
    
    if (!parsedData.success) {
        return res.status(400).json({
            message: "Incorrect format",
            error: parsedData.error.errors
        });
    }

    const { email, name, password } = parsedData.data;

    try {
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                message: "User with this email already exists"
            });
        }


        const hashedPassword = await bcrypt.hash(password, 12);
        
        await UserModel.create({
            email,
            password: hashedPassword,
            name
        });

        res.status(201).json({
            message: "You are signed up"
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({
            message: "Server error. Could not sign up"
        });
    }
});


app.post("/signin", async function (req, res) {
    const reqBody = z.object({
        email: z.string().email(),
        password: z.string().min(6).max(24)
    });

    const parsedData = reqBody.safeParse(req.body);

    if (!parsedData.success) {
        return res.status(400).json({
            message: "Incorrect format",
            error: parsedData.error.errors
        });
    }

    const { email, password } = parsedData.data;

    try {
        const user = await UserModel.findOne({ email });

        
        if (!user) {
            return res.status(403).json({
                message: "User does not exist"
            });
        }

       
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(403).json({
                message: "Incorrect credentials"
            });
        }

        // Generate JWT token
        const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "1h" });

        res.status(200).json({
            token
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({
            message: "Server error. Could not sign in"
        });
    }
});


app.post("/todo", auth, async function (req, res) {
    const reqBody = z.object({
        title: z.string().min(1).max(100),
        done: z.boolean()
    });

    const parsedData = reqBody.safeParse(req.body);

    if (!parsedData.success) {
        return res.status(400).json({
            message: "Incorrect format",
            error: parsedData.error.errors
        });
    }

    const { title, done } = parsedData.data;

    try {
        await TodoModel.create({
            userId: req.userId,
            title,
            done
        });

        res.status(201).json({
            message: "Todo created"
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({
            message: "Server error. Could not create todo"
        });
    }
});


app.get("/todos", auth, async function (req, res) {
    try {
        const todos = await TodoModel.find({ userId: req.userId });

        res.status(200).json({
            todos
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({
            message: "Server error. Could not fetch todos"
        });
    }
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});