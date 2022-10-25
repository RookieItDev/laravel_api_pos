<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    // Register
    public function register(Request $request) {

        // Validate field
        $fields = $request->validate([
            'fname' => 'required|string',
            'lname' => 'required|string',
            'username' => 'required|string',
            'password'=>'required',
            // 'password'=>'required|string|confirmed',
            'role'=>'required',

        ]);

        // Create user
        $user = User::create([
            'username' => $fields['username'],
            'password' => bcrypt($fields['password']), 
            'lname' => $fields['lname'],
            'fname' => $fields['fname'],
            'email' => 'email',
            'phone' => 'phone',
            'address' => 'address',
            'role' => $fields['role']
        ]);

        // Create token
        $token = $user->createToken($request->userAgent(), ["$user->role"])->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);

    }

    // Login
    public function login(Request $request) {

        // Validate field
        $fields = $request->validate([
            'username'=> 'required|string',
            'password'=>'required|string'
        ]);

        // Check email
        $user = User::where('username', $fields['username'])->first();

        // Check password
        if(!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'message' => 'Invalid login!'
            ], 401);
        }else{
            
            // ลบ token เก่าออกแล้วค่อยสร้างใหม่
            $user->tokens()->delete();

            // Create token
            $token = $user->createToken($request->userAgent(), ["$user->role"])->plainTextToken;
    
            $response = [
                'user' => $user,
                'token' => $token
            ];
    
            return response($response, 201);
        }

    }

    // Logout
    public function logout(Request $request){
        auth()->user()->tokens()->delete();
        return [
            'message' => 'Logged out'
        ];
    }

}