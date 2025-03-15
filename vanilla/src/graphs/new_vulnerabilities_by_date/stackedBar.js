import * as Plot from "@observablehq/plot";

// TODO: Implement increase/decrease rate lines

const START_DATE = "2022-01-01"
const END_DATE = "2022-12-31"

async function loadData(filename) {
    return await (await fetch(filename)).json();
}

/**
 * Aggregates data by week and severity, summing quantities
 * @param {Array} data - Array of objects with date, severity, and quantity properties
 * @returns {Array} - Aggregated data grouped by week and severity
 */
function aggregateDataBySeverityPerWeek(data) {
    // Create a map to store aggregated data
    const aggregatedMap = new Map();
    
    // Group data by week and severity
    data.forEach(item => {
        // Get the week start date (Sunday)
        const date = new Date(item.date);
        const day = date.getDay(); // 0 = Sunday, 1 = Monday, etc.
        const diff = date.getDate() - day;
        const weekStart = new Date(date);
        weekStart.setDate(diff);
        weekStart.setHours(0, 0, 0, 0);
        
        // Format week start date as YYYY-MM-DD for grouping
        const weekStr = weekStart.toISOString().split('T')[0];
        const key = `${weekStr}_${item.severity}`;
        
        if (!aggregatedMap.has(key)) {
            aggregatedMap.set(key, {
                date: weekStart, // Use the week start date
                severity: item.severity,
                quantity: 0,
                weekLabel: `Week of ${weekStart.toLocaleDateString()}`
            });
        }
        
        // Sum quantities
        aggregatedMap.get(key).quantity += item.quantity;
    });
    
    // Convert map to array
    return Array.from(aggregatedMap.values());
}

const data = await loadData("./src/graphs/new_vulnerabilities_by_date/data.json")
console.log(data)

data.forEach(d => d.date = new Date(d.date))
const filteredData = data.filter(d => d.date >= new Date(START_DATE) && d.date <= new Date(END_DATE));

// Aggregate data by severity per week
const aggregatedData = aggregateDataBySeverityPerWeek(filteredData);

const colorScale = {
    critical: 1,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
};

// Log the aggregated data to verify
console.log("Aggregated data by week:", aggregatedData);

const svg = Plot.plot({
    x: {
        label: "Week",
        tickFormat: d => {
            const date = new Date(d);
            return `${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
        }
    },
    y: {
        label: "Quantity",
        grid: true,
    },
    height: window.innerHeight,
    width: window.innerWidth,
    color: {
        scheme: "Turbo",
        legend: true,
        fontSize: 40,
        domain: Object.keys(colorScale),
        range: [1, 0.4],
    },
    marks: [
        Plot.rectY(
            aggregatedData,
            Plot.groupX(
                { y: "sum" },
                {
                    x: d => d.date,
                    y: d => d.quantity,
                    fill: d => d.severity,
                    interval: "week", // Using week interval for weekly aggregation
                    tip: {
                        fill: "black",
                        format: {
                            x: d => `Week of ${new Date(d).toLocaleDateString()}`,
                            y: d => d.toFixed(0)
                        }
                    },
                    order: Object.keys(colorScale),
                }
            )
        ),
    ]}
)

console.log(svg);

const div = document.querySelector("#myplot");

div.append(svg);