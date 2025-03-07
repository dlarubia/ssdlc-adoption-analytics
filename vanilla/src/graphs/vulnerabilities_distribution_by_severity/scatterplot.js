import * as Plot from "@observablehq/plot";
import * as d3 from "d3";

async function loadData(filename) {
    return await (await fetch(filename)).json();
}


const data = await loadData("./src/graphs/vulnerabilities_distribution_by_severity/data.json")
console.log(data)

const pRate = 0.95 // percentil by critical

// Agrupa os dados por "severity"
const quantilesByCategory = Array.from(d3.group(data, d => d.severity), ([severity, group]) => {
    const quantities = group.map(d => d.quantity);
    const quantile = d3.quantile(quantities, pRate);
    
    return {
        severity,
        quantile,
        pRate: pRate * 100 + "p",
        amountOfOutlines: quantities.filter(q => q > quantile).length, // Conta os elementos acima do quantil
    };
});
console.log(quantilesByCategory)

const severityDomains = ["critical", "high", "medium", "low", "info"]

console.log(quantilesByCategory);

const svg = Plot.plot({
    fx: {
        domain: severityDomains,
    },
    y: {
        grid: true,
    },
    marks: [
        
        Plot.dot(
            data, 
            Plot.dodgeX("middle", {
                fx: "severity", 
                y: "quantity", 
                fill: "bu",
                channels: {name: "repository"},
                tip: true,
        })),
        Plot.ruleY(quantilesByCategory, {
            y: "quantile",
            fx: "severity",
            stroke: "red",
            strokeDasharray: "4,4",
        }),
        Plot.text(quantilesByCategory, {
            text: "pRate",
            frameAnchor: "right",
            dx: 5,
            fx: "severity",
            // y: quantilesByCategory[0].quantile + 2,
            y: "quantile",
            dy: -8,
            fontSize: 16,
            fontFamily: "verdana",
            fontWeight: "normal",
            fill: "red",
        }),
        Plot.text(quantilesByCategory, {
           frameAnchor: "top",
           text: d => `amount: ${d.amountOfOutlines}`,
           fx: "severity",
        })
    ],
    height: window.innerHeight,
    width: window.innerWidth,
    color: {
        legend: true,
        fontSize: 40,
        scheme: "Turbo",
    },
})

console.log(svg)

const div = document.querySelector("#myplot");

div.append(svg);