import React, { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";

const Dashboard = () => {
    const [logins, setLogins] = useState([]);
    const [devices, setDevices] = useState([]);

    useEffect(() => {
        axios.get("http://localhost:5000/api/logins")
            .then(res => setLogins(res.data))
            .catch(err => console.error(err));

        axios.get("http://localhost:5000/api/devices")
            .then(res => setDevices(res.data))
            .catch(err => console.error(err));
    }, []);

    return (
        <div>
            <h1>Cybersecurity Dashboard</h1>
            
            <h2>Recent Logins</h2>
            <Link to="/recent-logins">View All Logins</Link>
            <ul>
                {logins.slice(0, 3).map((login) => ( // Show only 3 recent logins
                    <li key={login.id}>{login.user} - {new Date(login.time).toLocaleString()}</li>
                ))}
            </ul>

            <h2>Active Devices</h2>
            <ul>
                {devices.map((device) => (
                    <li key={device.id}>{device.device} - {device.status}</li>
                ))}
            </ul>
        </div>
    );
};

export default Dashboard;
