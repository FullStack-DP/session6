/*
{
  "name": "London in 7 Days Tour",
  "info": "Explore the best of London in 7 days with our expert guides. Visit iconic landmarks like the Tower of London, Buckingham Palace, and the British Museum. Enjoy guided walks through historic neighborhoods and experience the vibrant culture of this amazing city.",
  "image": "https://www.course-api.com/images/tours/tour-1.jpeg",
  "price": "2,195"
}
*/ 
 
let tourArray = [];
let nextId = 1;

function getAll() {
  return tourArray;
}

function addOne(tourData) {
  // Check if any parameter is empty or undefined
  const { name, info, image, price } = tourData;
  if (!name || !info || !image || !price) {
    return false;
  }

  const newItem = {
    id: nextId++,
    ...tourData,
  };

  tourArray.push(newItem);
  return newItem;
}

function findById(id) {
  const numericId = Number(id);
  const item = tourArray.find((item) => item.id === numericId);
  return item || false;
}

function updateOneById(id, updatedData) {
  const tour = findById(id);
  if (tour) {
    Object.assign(tour, updatedData); // Update properties using Object.assign
    return tour;
  }
  return false;
}

function deleteOneById(id) {
  const item = findById(id);
  if (item) {
    const initialLength = tourArray.length;
    tourArray = tourArray.filter((item) => item.id !== Number(id));
    return tourArray.length < initialLength; // Indicate successful deletion if the length has decreased
  }
  return false; // Return false if the item was not found
}

if (require.main === module) {
  // Add tour
  let result = addOne({
    name: "Best of Paris in 7 Days Tour",
    info: "On this tour, you'll enjoy guided neighborhood walks through the city's historic heart. Join us for the Best of Paris in 7 Days!",
    image: "https://www.course-api.com/images/tours/tour-2.jpeg",
    price: "1,995",
  });
  console.log("result", result);
  console.assert(typeof result === "object", "Result should be an object");

  // Add another tour
  result = addOne({
    name: "London in 7 Days Tour",
    info: "Explore the best of London in 7 days with our expert guides. Visit iconic landmarks like the Tower of London, Buckingham Palace, and the British Museum. Enjoy guided walks through historic neighborhoods and experience the vibrant culture of this amazing city.",
    image: "https://www.course-api.com/images/tours/tour-1.jpeg",
    price: "2,195",
  });
  console.log(result);
  console.assert(typeof result === "object", "Result should be an object");

  // Get all tours
  const allTours = getAll();
  console.log("getAll called:", allTours);
  console.assert(Array.isArray(allTours), "getAll should return an array");
  console.assert(
    allTours.length === 2,
    "getAll should return an array of length 2"
  );

  // Find tour by ID
  const tour = findById(1);
  console.log("findById called:", tour);
  console.assert(typeof tour === "object", "findById should return an object");

  // Update tour by ID
  const updatedTour = updateOneById(1, {
    price: "2,095",
    image: "https://www.course-api.com/images/tours/tour-1-updated.jpeg",
  });
  console.log("updateOneById called:", updatedTour);
  console.assert(
    typeof updatedTour === "object",
    "updateOneById should return an object"
  );

  // Verify update
  const updatedTourCheck = findById(1);
  console.log("findById called after item updated:", updatedTourCheck);
  console.assert(
    updatedTourCheck.price === "2,095" &&
      updatedTourCheck.image ===
        "https://www.course-api.com/images/tours/tour-1-updated.jpeg",
    "Tour should be updated"
  );

  // Delete tour by ID
  const deletedTour = deleteOneById(1);
  console.log("deleteOneById called:", deletedTour);
  console.assert(deletedTour === true, "deleteOneById should return true");

  // Verify deletion
  const deletedTourCheck = findById(1);
  console.log("findById called after item deleted:", deletedTourCheck);
  console.assert(deletedTourCheck === false, "Tour should be deleted");
}

const Tour = {
  getAll,
  addOne,
  findById,
  updateOneById,
  deleteOneById,
};

module.exports = Tour;
