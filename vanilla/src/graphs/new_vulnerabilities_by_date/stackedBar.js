import * as Plot from "@observablehq/plot";

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
            filteredData,
            Plot.groupX(
                { y: "sum" }, // Soma as quantidades por data e severidade
                {
                    x: d => new Date(d.date),  // Converte string em Date
                    y: d => d.quantity,
                    fill: d => d.severity,
                    interval: "week",
                    tip: true,
                    order: Object.keys(colorScale),
                }
            )
        ),
    ]}
)

console.log(svg);

const div = document.querySelector("#myplot");

div.append(svg);