import * as Plot from "@observablehq/plot";
import { axisBottom } from "d3";

// TODO: Implement increase/decrease rate lines

const START_DATE = "2022-01-01"
const END_DATE = "2022-12-31"

async function loadData(filename) {
    return await (await fetch(filename)).json();
}

const data = await loadData("./src/graphs/new_vulnerabilities_by_date/data.json")
console.log(data)

data.forEach(d => d.date = new Date(d.date))
const filteredData = data.filter(d => d.date >= new Date(START_DATE) && d.date <= new Date(END_DATE));

// Helper function to get the start of the week for a date
function getWeekStart(date) {
    const d = new Date(date);
    const day = d.getUTCDay();
    const diff = d.getUTCDate() - day + (day === 0 ? -6 : 1); // Adjust when day is Sunday
    d.setUTCDate(diff);
    d.setUTCHours(0, 0, 0, 0);
    return d;
}

// Aggregate data by week and severity, summing quantities across all repositories
function aggregateByWeekAndSeverity(data) {
    const aggregatedData = [];
    const weekSeverityMap = new Map();
    
    data.forEach(item => {
        const weekStart = getWeekStart(item.date);
        const key = `${weekStart.toISOString()}_${item.severity}`;
        
        if (weekSeverityMap.has(key)) {
            weekSeverityMap.get(key).quantity += item.quantity;
        } else {
            weekSeverityMap.set(key, {
                date: weekStart,
                severity: item.severity,
                quantity: item.quantity
            });
        }
    });
    
    return Array.from(weekSeverityMap.values());
}

// Apply the aggregation function to the filtered data
const aggregatedData = aggregateByWeekAndSeverity(filteredData);

// Log the original filtered data and the aggregated data for comparison
console.log("Original filtered data:", filteredData);
console.log("Aggregated data by week and severity:", aggregatedData);

// Log some statistics to verify aggregation
const totalOriginalQuantity = filteredData.reduce((sum, item) => sum + item.quantity, 0);
const totalAggregatedQuantity = aggregatedData.reduce((sum, item) => sum + item.quantity, 0);
console.log("Total quantity in original data:", totalOriginalQuantity);
console.log("Total quantity in aggregated data:", totalAggregatedQuantity);
console.log("Number of data points before aggregation:", filteredData.length);
console.log("Number of data points after aggregation:", aggregatedData.length);

const colorScale = {
    critical: 1,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
};

const svg = Plot.plot({
    x: {
        label: "Date",
        type: "band",  // For discrete bars
        tickRotate: 45,  // Rotate labels to avoid overlap
        tickPadding: 5,  // Add padding between tick and label
        tickSize: 8,     // Increase tick size for better visibility
        margin: 50,      // Add margin to accommodate rotated labels
        domain: [...new Set(aggregatedData.map(d => d.date.toISOString().split('T')[0]))].sort(),  // Ensure all dates are included
        tickFormat: (d, i, ticks) => {
            // Only show a subset of ticks to avoid overlap
            const tickCount = ticks.length;
            // Adjust this logic based on your data density
            if (tickCount > 20) {
                return i % Math.ceil(tickCount / 10) === 0 ? d : "";
            }
            return d;
        }
    },
    y: {
        label: "Quantity",
        grid: true,
    },
    height: window.innerHeight,
    width: window.innerWidth,
    marginBottom: 80,
    // padding: 0,
    color: {
        scheme: "Turbo",
        legend: true,
        fontSize: 40,
        domain: Object.keys(colorScale),
        range: [1, 0.4],
    },
    marks: [
        Plot.barY(
            aggregatedData,
            {
                x: d => d.date.toISOString().split('T')[0],  // Convert date to string format YYYY-MM-DD
                y: d => d.quantity,
                fill: d => d.severity,
                tip: {
                    fill: "black",
                },
                order: Object.keys(colorScale),
                stroke: "white",
                strokeOpacity: 0.3
            }
        ),
    ]}
)

console.log(svg);

const div = document.querySelector("#myplot");
div.append(svg);