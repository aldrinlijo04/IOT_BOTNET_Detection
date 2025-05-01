import React, { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

const RecentLogins = () => {
    const [logins, setLogins] = useState([]);

    useEffect(() => {
        axios.get("http://localhost:5000/api/logins")
            .then(res => setLogins(res.data))
            .catch(err => console.error(err));
    }, []);

    return (
        <div>
            <h1>Recent Logins</h1>
            <Link to="/dashboard">Back to Dashboard</Link>
            <ul>
                {logins.map((login) => (
                    <li key={login.id}>{login.user} - {new Date(login.time).toLocaleString()}</li>
                ))}
            </ul>
        </div>
    );
};

export default RecentLogins;
