package de.hpi.spark_tutorial

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._

object Sindy {


  def discoverINDs(inputs: List[String], spark: SparkSession): Unit = {

    import spark.implicits._

    println(inputs)

    val inputData = inputs.toStream.map(input => spark.read
      .option("inferSchema", "true")
      .option("header", "true")
      .option("delimiter", ";")
      .csv(input))

    println(s"${java.time.LocalTime.now()} DATA READ SUCCESSFULLY ")
    println("---------------------------------------------------------------------------------------------------------")
    println(s"${java.time.LocalTime.now()} MAP COLUMNS BY VALUE...")

    //map and reduce by value
    val columnData = inputData
      .flatMap(df => df.columns
        .map(c => df.select(c)
          .distinct()
          .withColumn("nameColumn", lit(c))
          .toDF("valueColumn", "nameColumn"))
      ).reduce((t1, t2) => t1.union(t2))

    //    columnData.show()
    println(s"${java.time.LocalTime.now()} MAPPING COLUMNS BY VALUE FINISHED")
    println("---------------------------------------------------------------------------------------------------------")
    println(s"${java.time.LocalTime.now()} GROUP COLUMNS BY VALUE...")

    // union attributes by value
    val valueColumns = columnData
      .as[(String, String)]
      .groupByKey(t => t._1)
      .mapGroups((key, iterator) =>
        (key, iterator
          .map(t => Set(t._2))
          .reduce((a, b) => a union b)))

    //    valueColumns.show()
    println(s"${java.time.LocalTime.now()} GROUP COLUMNS BY VALUE FINISHED")
    println("---------------------------------------------------------------------------------------------------------")
    println(s"${java.time.LocalTime.now()} GENERATE INDS LISTS...")

    //generate IND lists
    val inds = valueColumns
      .map(t => generateINDList(t._2))
      .toDF("INDS")
      .withColumn("INDS", explode($"INDS"))
    //    inds.show()

    println(s"${java.time.LocalTime.now()} GENERATING INDS LISTS FINISHED")
    println("---------------------------------------------------------------------------------------------------------")
    println(s"${java.time.LocalTime.now()} GROUP INDS BY VALUE...")

    //reduce by first attribute and intersect attributes
    val intersected = inds.select("INDS.*")
      .as[(String, Set[String])]
      .groupByKey(t => t._1)
      .mapGroups((key, iterator) =>
        (key, iterator
          .map(t => t._2)
          .reduce((a, b) => a intersect b)))
      .toDF("Column", "IND")
    //    intersected.show()
    println(s"${java.time.LocalTime.now()} GROUP INDS BY VALUE FINISHED")
    println("---------------------------------------------------------------------------------------------------------")
    println(s"${java.time.LocalTime.now()} FILTER AND COLLECT RESULTS ...")

    val result = intersected
      .filter(size($"IND") > 0)
      .as[(String, Set[String])]
      .map(t => (t._1, t._2.mkString(", ")))
      .toDF("Column", "IND")
      .sort($"Column")
      .collect()

    println(s"${java.time.LocalTime.now()} FILTER AND COLLECT RESULTS FINISHED")
    println("---------------------------------------------------------------------------------------------------------")
    println(s"${java.time.LocalTime.now()} RESULTS:")
    result.foreach(ind => println(ind(0) + " < " + ind(1)))
  }

  def generateINDList(list: Set[String]): Array[(String, Set[String])] = {
    var result = Array[(String, Set[String])]()
    list.foreach(elem => result = result :+ (elem, list - elem))
    result
  }

}
